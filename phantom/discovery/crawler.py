"""
phantom/discovery/crawler.py

Async web crawler — feeds URLs into the fingerprinter and classifier.

Two-speed design:
  Fast path  — httpx for plain HTML pages. Cheap, concurrent, fine for most targets.
  Slow path  — Playwright for SPAs (React/Vue/Angular). Kicks in automatically
               when httpx gets back a page that's mostly empty divs and JS bundles.

Why Playwright matters:
  Every modern enterprise chatbot is a SPA. Without JS rendering you're scanning
  the skeleton — a <div id="root"> and 14 script tags. Playwright runs real Chromium,
  waits for network idle, and gives you the actual rendered DOM including dynamically
  injected chat widgets and input forms.

  Cost: ~3-5s per SPA page vs ~0.3s for plain HTML. We only pay this when the
  fast path clearly failed, so overall crawl stays fast on plain sites.

SPA detection heuristics (any 2 triggers Playwright):
  1. Response body < 2KB for an HTML page
  2. Body contains <div id="root"> or <div id="app"> with no text content
  3. Body contains 3+ <script src="...chunk..."> tags (bundled JS)
  4. Text/HTML ratio < 5%

Playwright is optional — if not installed the crawler logs a warning and continues
with httpx only. Install: pip install playwright && playwright install chromium
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup

from phantom.core.config import PhantomConfig
from phantom.core.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_QUEUE_MAXSIZE: int = 1000
_CRAWL_JOIN_TIMEOUT: float = 300.0

# Playwright timeouts — generous because enterprise apps can be slow
_PLAYWRIGHT_TIMEOUT_MS: int = 15_000

# ---------------------------------------------------------------------------
# SPA detection
# ---------------------------------------------------------------------------

# Script src patterns that indicate a bundled JS app (webpack/vite/rollup)
_BUNDLE_SCRIPT_RE = re.compile(
    r'<script[^>]+src=["\'][^"\']*(?:chunk|bundle|main|app|index)\.[a-f0-9]+\.js["\']',
    re.IGNORECASE,
)

# Root mount points used by React, Vue, Angular, Svelte
_SPA_ROOT_RE = re.compile(
    r'<div[^>]+id=["\'](?:root|app|__next|__nuxt|ember\d*)["\']',
    re.IGNORECASE,
)


def _looks_like_spa(body: str, content_type: str) -> bool:
    """
    Return True if this response looks like an SPA shell that needs JS rendering.

    Requires at least 2 of 4 signals to avoid false positives on legitimate
    short pages. The cost of missing a chatbot surface is much higher than
    spending 3s extra on a plain page.
    """
    if "html" not in content_type:
        return False

    signals = 0

    if len(body.strip()) < 2048:
        signals += 1

    if _SPA_ROOT_RE.search(body):
        signals += 1

    if len(_BUNDLE_SCRIPT_RE.findall(body)) >= 3:
        signals += 1

    if body:
        text = BeautifulSoup(body, "html.parser").get_text()
        if len(body) > 0 and len(text) / len(body) < 0.05:
            signals += 1

    return signals >= 2


# ---------------------------------------------------------------------------
# Playwright rendering
# ---------------------------------------------------------------------------

# Cached import state — don't try to import repeatedly if it failed once
_playwright_available: Optional[bool] = None


async def _render_with_playwright(
    url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    ssl_verify: bool,
) -> Optional[str]:
    """
    Load a URL in headless Chromium and return the fully rendered HTML.

    Waits for networkidle before extracting the DOM so dynamically injected
    widgets (chat boxes, AI search bars) are present in the output.

    Blocks images/fonts/media — we only need the DOM, not the pixels.

    Returns None if Playwright isn't installed or the page fails to load.
    """
    global _playwright_available

    if _playwright_available is False:
        return None

    try:
        from playwright.async_api import async_playwright, Error as PlaywrightError
        _playwright_available = True
    except ImportError:
        if _playwright_available is None:
            log.warning(
                "[crawler] Playwright not installed — JS rendering disabled. "
                "Install: pip install playwright && playwright install chromium"
            )
        _playwright_available = False
        return None

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            ctx = await browser.new_context(
                extra_http_headers=headers,
                ignore_https_errors=not ssl_verify,
            )

            # Inject auth cookies into the browser context
            if cookies:
                parsed = urlparse(url)
                await ctx.add_cookies([
                    {"name": k, "value": v, "domain": parsed.netloc, "path": "/"}
                    for k, v in cookies.items()
                ])

            page = await ctx.new_page()

            # Block heavy assets — cuts load time significantly on media-heavy apps
            await page.route(
                "**/*.{png,jpg,jpeg,gif,webp,svg,ico,woff,woff2,ttf,eot,mp4,mp3,wav}",
                lambda route: route.abort(),
            )

            try:
                await page.goto(url, wait_until="networkidle", timeout=_PLAYWRIGHT_TIMEOUT_MS)
            except PlaywrightError:
                # networkidle timed out — grab whatever DOM we have, still useful
                log.debug("[playwright] networkidle timeout on %s — using partial DOM", url)

            rendered_html = await page.content()
            await browser.close()

            log.debug("[playwright] Rendered %s — %d bytes", url, len(rendered_html))
            return rendered_html

    except Exception as exc:
        log.warning("[playwright] Render failed on %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FormField:
    name: str
    field_type: str
    value: str = ""


@dataclass
class CrawlTarget:
    """A discovered input surface, ready for fingerprinting."""
    url: str
    method: str = "GET"
    depth: int = 0
    form_fields: list[FormField] = field(default_factory=list)
    page_title: str = ""
    content_type: str = ""
    status_code: int = 0
    response_text: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    latency_ms: float = 0.0
    # True when this page was rendered by Playwright rather than plain httpx.
    # Fingerprinter uses this to weight AI surface confidence higher — if we
    # needed Playwright, there's almost certainly a JS-heavy frontend here.
    js_rendered: bool = False

    @property
    def is_form(self) -> bool:
        return bool(self.form_fields)

    @property
    def parsed_url(self):
        return urlparse(self.url)


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

class _TokenBucket:
    def __init__(self, rate: float, burst: int) -> None:
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            if self._tokens < 1.0:
                sleep_for = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(sleep_for)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


# ---------------------------------------------------------------------------
# Robots.txt helper
# ---------------------------------------------------------------------------

def _build_robots_parser(robots_txt: str, base_url: str) -> RobotFileParser:
    rp = RobotFileParser()
    rp.set_url(base_url + "/robots.txt")
    rp.parse(robots_txt.splitlines())
    return rp


def _is_safe_path(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if ".." in parsed.path or parsed.path.startswith("//"):
            return False
        if parsed.scheme and parsed.scheme not in ("http", "https"):
            return False
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main crawler
# ---------------------------------------------------------------------------

class Crawler:
    def __init__(self, config: PhantomConfig) -> None:
        self._cfg = config
        self._visited: set[str] = set()
        self._queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        self._semaphore = asyncio.Semaphore(config.crawl_concurrency)
        self._bucket = _TokenBucket(config.rate_limit_rps, config.rate_limit_burst)
        self._allowed_netlocs: frozenset[str] = frozenset(
            urlparse(d if d.startswith("http") else f"http://{d}").netloc or d
            for d in config.allowed_domains
        )
        self._robots: Optional[RobotFileParser] = None
        self._results: list[CrawlTarget] = []
        self.failed_urls: list[str] = []
        self._spa_count: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def crawl(self) -> list[CrawlTarget]:
        """
        Start crawl from config.target_url.
        Returns all discovered CrawlTargets (pages + forms).
        """
        start = self._cfg.target_url
        log.info("Starting crawl from [url]%s[/url]", start)

        async with httpx.AsyncClient(
            headers=self._cfg.headers,
            timeout=self._cfg.crawl_timeout,
            follow_redirects=True,
            verify=self._cfg.ssl_verify,
            limits=httpx.Limits(max_connections=self._cfg.crawl_concurrency * 2),
        ) as client:
            if self._cfg.respect_robots:
                await self._load_robots(client, start)

            await self._queue.put((start, 0))

            workers = [
                asyncio.create_task(self._worker(client))
                for _ in range(self._cfg.crawl_concurrency)
            ]

            try:
                await asyncio.wait_for(self._queue.join(), timeout=_CRAWL_JOIN_TIMEOUT)
            except asyncio.TimeoutError:
                log.warning(
                    "Crawl queue did not drain within %.0fs — cancelling workers. "
                    "%d items may remain unprocessed.",
                    _CRAWL_JOIN_TIMEOUT,
                    self._queue.qsize(),
                )

            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        plain  = len([r for r in self._results if not r.is_form and not r.js_rendered])
        spa    = len([r for r in self._results if not r.is_form and r.js_rendered])
        forms  = len([r for r in self._results if r.is_form])

        log.info(
            "Crawl complete — %d plain pages, %d SPA pages (JS rendered), "
            "%d forms, %d failed",
            plain, spa, forms, len(self.failed_urls),
        )
        return self._results

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    async def _worker(self, client: httpx.AsyncClient) -> None:
        while True:
            url, depth = await self._queue.get()
            try:
                await self._process(client, url, depth)
            except Exception as exc:
                log.debug("Worker error on %s: %s", url, exc)
            finally:
                self._queue.task_done()

    async def _process(self, client: httpx.AsyncClient, url: str, depth: int) -> None:
        if url in self._visited:
            return
        if len(self._visited) >= self._cfg.max_pages:
            return
        if not _is_safe_path(url):
            log.warning("Unsafe path, skipping: %s", url)
            return
        if not self._in_scope(url):
            log.debug("Out of scope, skipping: %s", url)
            return
        if self._robots and not self._robots.can_fetch(self._cfg.user_agent, url):
            log.debug("robots.txt disallows: %s", url)
            return

        self._visited.add(url)
        await self._bucket.acquire()

        async with self._semaphore:
            target = await self._fetch(client, url, depth)

        if target is None:
            return

        self._results.append(target)
        log.debug(
            "Crawled [%d%s] %s",
            target.status_code,
            " JS" if target.js_rendered else "",
            url,
        )

        if depth >= self._cfg.max_depth:
            return

        for link in self._extract_links(target):
            if link not in self._visited:
                await self._queue.put((link, depth + 1))

        for form_target in self._extract_forms(target):
            self._results.append(form_target)
            log.debug(
                "  Found form → %s (%d fields)",
                form_target.url, len(form_target.form_fields),
            )

    # ------------------------------------------------------------------
    # Fetching — fast path (httpx) then SPA fallback (Playwright)
    # ------------------------------------------------------------------

    async def _fetch(
        self, client: httpx.AsyncClient, url: str, depth: int
    ) -> Optional[CrawlTarget]:
        """
        Fetch a URL. Uses httpx first; falls back to Playwright if the
        response looks like an SPA shell that needs JS rendering.
        """
        try:
            t0 = time.monotonic()
            response = await client.get(url)
            latency_ms = (time.monotonic() - t0) * 1000

            content_type = response.headers.get("content-type", "")
            body = ""
            if "text" in content_type or "json" in content_type or "javascript" in content_type:
                body = response.text

            js_rendered = False

            if _looks_like_spa(body, content_type):
                log.info("[crawler] SPA detected at %s — switching to Playwright", url)

                # ssl_verify can be bool or str (cert path) — Playwright only takes bool
                ssl_ok = self._cfg.ssl_verify if isinstance(self._cfg.ssl_verify, bool) else True

                rendered = await _render_with_playwright(
                    url=url,
                    headers=self._cfg.headers,
                    cookies=self._cfg.session_cookies,
                    ssl_verify=ssl_ok,
                )

                if rendered:
                    body = rendered
                    content_type = "text/html"
                    js_rendered = True
                    self._spa_count += 1
                else:
                    # Playwright not installed or failed — carry on with the shell,
                    # at least the fingerprinter gets something
                    log.debug("[crawler] Playwright unavailable, using shell for %s", url)

            title = ""
            if "html" in content_type and body:
                soup = BeautifulSoup(body, "html.parser")
                title_tag = soup.find("title")
                title = title_tag.get_text(strip=True) if title_tag else ""

            return CrawlTarget(
                url=str(response.url),
                depth=depth,
                page_title=title,
                content_type=content_type,
                status_code=response.status_code,
                response_text=body,
                response_headers=dict(response.headers),
                latency_ms=latency_ms,
                js_rendered=js_rendered,
            )

        except httpx.TimeoutException:
            log.warning("Timeout fetching %s", url)
            self.failed_urls.append(url)
        except httpx.RequestError as exc:
            log.warning("Request error on %s: %s", url, exc)
            self.failed_urls.append(url)
        return None

    # ------------------------------------------------------------------
    # Link + form extraction
    # ------------------------------------------------------------------

    def _extract_links(self, target: CrawlTarget) -> list[str]:
        if not target.response_text or "html" not in target.content_type:
            return []

        soup = BeautifulSoup(target.response_text, "html.parser")
        links: list[str] = []

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            absolute = urljoin(target.url, href)
            normalized = self._normalize_url(absolute)
            if normalized and self._in_scope(normalized):
                links.append(normalized)

        return links

    def _extract_forms(self, target: CrawlTarget) -> list[CrawlTarget]:
        if not target.response_text or "html" not in target.content_type:
            return []

        soup = BeautifulSoup(target.response_text, "html.parser")
        form_targets: list[CrawlTarget] = []

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method", "GET")).upper()
            action_url = urljoin(target.url, action) if action else target.url
            action_url = self._normalize_url(action_url)
            if not action_url:
                continue

            fields: list[FormField] = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name") or inp.get("id") or ""
                if not name:
                    continue
                fields.append(FormField(
                    name=name,
                    field_type=inp.get("type", inp.name or "text"),
                    value=inp.get("value", ""),
                ))

            if fields:
                form_targets.append(CrawlTarget(
                    url=action_url,
                    method=method,
                    depth=target.depth,
                    form_fields=fields,
                    page_title=target.page_title,
                    # If the form came from a JS-rendered page, flag it —
                    # fingerprinter uses this to boost AI surface confidence
                    js_rendered=target.js_rendered,
                ))

        return form_targets

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _in_scope(self, url: str) -> bool:
        if not self._cfg.scope_strict:
            return True
        netloc = urlparse(url).netloc
        if not netloc:
            return False
        for allowed in self._allowed_netlocs:
            if netloc == allowed or netloc.endswith("." + allowed):
                return True
        return False

    @staticmethod
    def _normalize_url(url: str) -> Optional[str]:
        try:
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                return None
            return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
        except Exception:
            return None

    async def _load_robots(self, client: httpx.AsyncClient, base_url: str) -> None:
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            r = await client.get(robots_url)
            if r.status_code == 200:
                self._robots = _build_robots_parser(r.text, f"{parsed.scheme}://{parsed.netloc}")
                log.debug("Loaded robots.txt from %s", robots_url)
        except Exception as exc:
            log.debug("Could not fetch robots.txt: %s", exc)