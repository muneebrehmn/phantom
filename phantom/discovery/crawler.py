"""
phantom/discovery/crawler.py

Async web crawler that feeds URLs to the fingerprinter and classifier.

Design decisions:
- Uses httpx.AsyncClient with connection pooling — one client for the whole
  crawl, not one per request.  This respects keep-alive and avoids the TLS
  handshake overhead of re-connecting to the same origin repeatedly.
- asyncio.Semaphore enforces concurrency cap so we don't hammer the target.
- Rate limiting is a simple token-bucket implemented with asyncio.sleep
  rather than pulling in a library — keeps the dep tree small.
- Scope enforcement is a whitelist of allowed netlocs extracted from
  config.allowed_domains.  Off-scope links are logged at DEBUG, not silently
  dropped, so the operator can audit what was excluded.
- Forms are extracted as CrawlTargets with method/action/fields so the
  payload engine can POST to them later without re-crawling.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup

from phantom.core.config import PhantomConfig
from phantom.core.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FormField:
    name: str
    field_type: str          # text, textarea, hidden, search, …
    value: str = ""


@dataclass
class CrawlTarget:
    """Represents a discovered input surface before fingerprinting."""
    url: str
    method: str = "GET"       # GET or POST
    depth: int = 0
    form_fields: list[FormField] = field(default_factory=list)
    page_title: str = ""
    content_type: str = ""
    status_code: int = 0
    # Raw response text — used downstream by fingerprinter/classifier
    response_text: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    latency_ms: float = 0.0

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
        self._rate = rate          # tokens per second
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


# ---------------------------------------------------------------------------
# Main crawler
# ---------------------------------------------------------------------------

class Crawler:
    def __init__(self, config: PhantomConfig) -> None:
        self._cfg = config
        self._visited: set[str] = set()
        self._queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(config.crawl_concurrency)
        self._bucket = _TokenBucket(config.rate_limit_rps, config.rate_limit_burst)
        self._allowed_netlocs: frozenset[str] = frozenset(
            urlparse(d if d.startswith("http") else f"http://{d}").netloc or d
            for d in config.allowed_domains
        )
        self._robots: Optional[RobotFileParser] = None
        self._results: list[CrawlTarget] = []

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
            limits=httpx.Limits(max_connections=self._cfg.crawl_concurrency * 2),
        ) as client:
            if self._cfg.respect_robots:
                await self._load_robots(client, start)

            await self._queue.put((start, 0))

            workers = [
                asyncio.create_task(self._worker(client))
                for _ in range(self._cfg.crawl_concurrency)
            ]
            await self._queue.join()

            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        log.info("Crawl complete — %d pages, %d forms discovered",
                 len([r for r in self._results if not r.is_form]),
                 len([r for r in self._results if r.is_form]))
        return self._results

    # ------------------------------------------------------------------
    # Internal
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
        log.debug("Crawled [%d] %s", target.status_code, url)

        # Don't extract links beyond max_depth
        if depth >= self._cfg.max_depth:
            return

        for link in self._extract_links(target):
            if link not in self._visited:
                await self._queue.put((link, depth + 1))

        for form_target in self._extract_forms(target):
            self._results.append(form_target)
            log.debug("  Found form → %s (%d fields)", form_target.url,
                      len(form_target.form_fields))

    async def _fetch(
        self, client: httpx.AsyncClient, url: str, depth: int
    ) -> Optional[CrawlTarget]:
        try:
            t0 = time.monotonic()
            response = await client.get(url)
            latency_ms = (time.monotonic() - t0) * 1000

            content_type = response.headers.get("content-type", "")
            body = ""
            # Only decode text responses — skip binary assets
            if "text" in content_type or "json" in content_type or "javascript" in content_type:
                body = response.text

            title = ""
            if "html" in content_type and body:
                soup = BeautifulSoup(body, "html.parser")
                title_tag = soup.find("title")
                title = title_tag.get_text(strip=True) if title_tag else ""

            return CrawlTarget(
                url=str(response.url),   # use final URL after redirects
                depth=depth,
                page_title=title,
                content_type=content_type,
                status_code=response.status_code,
                response_text=body,
                response_headers=dict(response.headers),
                latency_ms=latency_ms,
            )

        except httpx.TimeoutException:
            log.warning("Timeout fetching %s", url)
        except httpx.RequestError as exc:
            log.warning("Request error on %s: %s", url, exc)
        return None

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
                ))

        return form_targets

    def _in_scope(self, url: str) -> bool:
        if not self._cfg.scope_strict:
            return True
        netloc = urlparse(url).netloc
        if not netloc:
            return False
        # Match exact domain or subdomain of allowed
        for allowed in self._allowed_netlocs:
            if netloc == allowed or netloc.endswith("." + allowed):
                return True
        return False

    @staticmethod
    def _normalize_url(url: str) -> Optional[str]:
        """Strip fragments, normalize scheme. Returns None for non-http URLs."""
        try:
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                return None
            # Drop fragment, keep everything else
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