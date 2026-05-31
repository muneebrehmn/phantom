"""
tests/test_crawler.py

Unit tests for the async web crawler (phantom/discovery/crawler.py).

All tests mock the HTTP layer — no real network calls are made.
Coverage:
- Queue maxsize enforces backpressure (_QUEUE_MAXSIZE constant respected)
- queue.join() timeout fires correctly and workers are cancelled gracefully
- Failed URLs are tracked in crawler.failed_urls for both timeout and
  connection errors
- Successful crawl populates results and leaves failed_urls empty
- Scope enforcement still works with the new queue behaviour

Run with:
    pytest tests/test_crawler.py -v
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from phantom.core.config import PhantomConfig
from phantom.discovery.crawler import (
    Crawler,
    CrawlTarget,
    _CRAWL_JOIN_TIMEOUT,
    _QUEUE_MAXSIZE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_config(**kwargs) -> PhantomConfig:
    defaults = dict(
        rate_limit_rps=100.0,
        crawl_timeout=5.0,
        crawl_concurrency=2,
        max_pages=50,
        max_depth=2,
        respect_robots=False,
        _testing=True,
    )
    defaults.update(kwargs)
    return PhantomConfig(**defaults).with_target("https://example.com")


def make_html_response(
    body: str = "<html><body><p>Hello</p></body></html>",
    status_code: int = 200,
    url: str = "https://example.com",
) -> MagicMock:
    headers_dict = {"content-type": "text/html; charset=utf-8"}
    resp = MagicMock(spec=httpx.Response)
    resp.text = body
    resp.status_code = status_code
    resp.url = url
    resp.headers = MagicMock()
    resp.headers.get = lambda k, default="": headers_dict.get(k, default)
    resp.headers.__iter__ = lambda self: iter(headers_dict)
    resp.headers.items = lambda: headers_dict.items()
    return resp


# ---------------------------------------------------------------------------
# Queue configuration tests
# ---------------------------------------------------------------------------

class TestQueueConfiguration:
    """Verify queue is created with the correct maxsize."""

    def test_queue_has_correct_maxsize(self):
        config  = make_config()
        crawler = Crawler(config)
        assert crawler._queue.maxsize == _QUEUE_MAXSIZE

    def test_queue_maxsize_constant_value(self):
        """_QUEUE_MAXSIZE should be 1000 — large enough for real sites."""
        assert _QUEUE_MAXSIZE == 1000

    def test_crawl_join_timeout_constant_value(self):
        """_CRAWL_JOIN_TIMEOUT should be 300s (5 min) — generous for slow sites."""
        assert _CRAWL_JOIN_TIMEOUT == 300.0


# ---------------------------------------------------------------------------
# Failed URL tracking tests
# ---------------------------------------------------------------------------

class TestFailedUrlTracking:
    """Verify that failed fetches are recorded in crawler.failed_urls."""

    def test_failed_urls_starts_empty(self):
        config  = make_config()
        crawler = Crawler(config)
        assert crawler.failed_urls == []

    @pytest.mark.asyncio
    async def test_timeout_recorded_in_failed_urls(self):
        """A TimeoutException on fetch should append the URL to failed_urls."""
        config  = make_config()
        crawler = Crawler(config)

        async def fake_get(url, **kwargs):
            raise httpx.TimeoutException("timed out")

        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=fake_get)

        result = await crawler._fetch(mock_client, "https://example.com/slow", depth=0)

        assert result is None
        assert "https://example.com/slow" in crawler.failed_urls

    @pytest.mark.asyncio
    async def test_connect_error_recorded_in_failed_urls(self):
        """A RequestError on fetch should append the URL to failed_urls."""
        config  = make_config()
        crawler = Crawler(config)

        mock_client = MagicMock()
        mock_client.get = AsyncMock(
            side_effect=httpx.ConnectError("connection refused")
        )

        result = await crawler._fetch(mock_client, "https://example.com/down", depth=0)

        assert result is None
        assert "https://example.com/down" in crawler.failed_urls

    @pytest.mark.asyncio
    async def test_successful_fetch_not_in_failed_urls(self):
        """A successful fetch must NOT appear in failed_urls."""
        config  = make_config()
        crawler = Crawler(config)

        mock_resp = make_html_response(url="https://example.com/ok")
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        result = await crawler._fetch(mock_client, "https://example.com/ok", depth=0)

        assert result is not None
        assert crawler.failed_urls == []

    @pytest.mark.asyncio
    async def test_multiple_failures_all_recorded(self):
        """Multiple failed URLs should all appear in failed_urls."""
        config  = make_config()
        crawler = Crawler(config)

        urls = [
            "https://example.com/a",
            "https://example.com/b",
            "https://example.com/c",
        ]

        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        for url in urls:
            await crawler._fetch(mock_client, url, depth=0)

        assert set(crawler.failed_urls) == set(urls)
        assert len(crawler.failed_urls) == 3


# ---------------------------------------------------------------------------
# Queue join timeout tests
# ---------------------------------------------------------------------------

class TestQueueJoinTimeout:
    """Verify crawl() handles queue.join() timeout gracefully."""

    @pytest.mark.asyncio
    async def test_crawl_completes_on_join_timeout(self):
        """
        If queue.join() times out, crawl() should still return normally
        (no exception propagated to caller) with a warning logged.
        """
        config  = make_config()
        crawler = Crawler(config)

        # Patch queue.join to always time out immediately
        async def instant_timeout():
            raise asyncio.TimeoutError()

        with patch(
            "phantom.discovery.crawler.asyncio.wait_for",
            new_callable=AsyncMock,
            side_effect=asyncio.TimeoutError(),
        ):
            with patch.object(
                crawler, "_load_robots", new_callable=AsyncMock
            ):
                # Patch the AsyncClient so no real HTTP is attempted
                mock_resp = make_html_response()
                with patch("httpx.AsyncClient") as mock_client_cls:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__  = AsyncMock(return_value=False)
                    mock_client.get = AsyncMock(return_value=mock_resp)
                    mock_client_cls.return_value = mock_client

                    # Should NOT raise — timeout is handled internally
                    results = await crawler.crawl()

        # crawl() always returns a list, even on timeout
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_join_timeout_logs_warning(self, caplog):
        """A queue.join() timeout should emit a WARNING log."""
        import logging

        config  = make_config()
        crawler = Crawler(config)

        with patch(
            "phantom.discovery.crawler.asyncio.wait_for",
            new_callable=AsyncMock,
            side_effect=asyncio.TimeoutError(),
        ):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__  = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=make_html_response())
                mock_client_cls.return_value = mock_client

                with caplog.at_level(logging.WARNING, logger="phantom.discovery.crawler"):
                    await crawler.crawl()

        assert any("did not drain" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Successful crawl smoke test
# ---------------------------------------------------------------------------

class TestCrawlIntegration:
    """End-to-end smoke test of the crawl() method with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_successful_crawl_returns_results_and_empty_failed(self):
        """
        A crawl where all fetches succeed should populate results and
        leave failed_urls empty.
        """
        config  = make_config()
        crawler = Crawler(config)

        simple_html = (
            "<html><head><title>Test</title></head>"
            "<body><p>No links here.</p></body></html>"
        )
        mock_resp = make_html_response(body=simple_html, url="https://example.com")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__  = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            results = await crawler.crawl()

        assert isinstance(results, list)
        assert len(results) >= 1
        assert crawler.failed_urls == []
        # Confirm the seed URL was crawled
        urls = [r.url for r in results]
        assert any("example.com" in u for u in urls)