"""
tests/test_auth.py

Unit tests for authenticated scanning support.

Coverage:
- _parse_auth_args correctly parses --auth-bearer, --auth-header, --auth-cookie
- Multiple flags of the same type are all collected
- Bearer shorthand writes correct Authorization header
- --auth-header and --auth-cookie with bad separators exit with error
- Auth credentials flow into PhantomConfig.custom_headers / .session_cookies
- Config.headers property merges auth headers with User-Agent
- All three flags can be combined in one invocation

Run with:
    pytest tests/test_auth.py -v
"""

from __future__ import annotations

import sys
from argparse import Namespace
from unittest.mock import patch

import pytest

# Import the helper under test
import importlib, types

# We import phantom.py as a module (it's not in a package)
import importlib.util, pathlib

_phantom_path = pathlib.Path(__file__).parent.parent / "phantom.py"
_spec = importlib.util.spec_from_file_location("phantom_cli", _phantom_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

_parse_auth_args = _mod._parse_auth_args
build_parser     = _mod.build_parser

from phantom.core.config import PhantomConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_args(**kwargs) -> Namespace:
    """Build a minimal Namespace mimicking argparse output."""
    defaults = dict(
        auth_bearer="",
        auth_headers=[],
        auth_cookies=[],
    )
    defaults.update(kwargs)
    return Namespace(**defaults)


def make_config(**kwargs) -> PhantomConfig:
    defaults = dict(rate_limit_rps=1.0, _testing=True)
    defaults.update(kwargs)
    return PhantomConfig(**defaults).with_target("https://example.com")


# ---------------------------------------------------------------------------
# _parse_auth_args — bearer
# ---------------------------------------------------------------------------

class TestAuthBearer:
    def test_bearer_sets_authorization_header(self):
        args = make_args(auth_bearer="mytoken123")
        headers, cookies = _parse_auth_args(args)
        assert headers["Authorization"] == "Bearer mytoken123"
        assert cookies == {}

    def test_bearer_empty_string_produces_no_header(self):
        args = make_args(auth_bearer="")
        headers, cookies = _parse_auth_args(args)
        assert "Authorization" not in headers

    def test_bearer_with_jwt_style_token(self):
        token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"
        args = make_args(auth_bearer=token)
        headers, _ = _parse_auth_args(args)
        assert headers["Authorization"] == f"Bearer {token}"


# ---------------------------------------------------------------------------
# _parse_auth_args — --auth-header
# ---------------------------------------------------------------------------

class TestAuthHeader:
    def test_single_header_parsed(self):
        args = make_args(auth_headers=["X-API-Key:secret"])
        headers, _ = _parse_auth_args(args)
        assert headers["X-API-Key"] == "secret"

    def test_multiple_headers_all_collected(self):
        args = make_args(auth_headers=["X-API-Key:key1", "X-Tenant-ID:acme"])
        headers, _ = _parse_auth_args(args)
        assert headers["X-API-Key"] == "key1"
        assert headers["X-Tenant-ID"] == "acme"

    def test_header_value_with_colons_preserved(self):
        """Values can themselves contain colons (e.g. timestamps, URLs)."""
        args = make_args(auth_headers=["X-Timestamp:2024:01:01"])
        headers, _ = _parse_auth_args(args)
        # Only first colon is the separator
        assert headers["X-Timestamp"] == "2024:01:01"

    def test_header_whitespace_stripped_from_name(self):
        args = make_args(auth_headers=["  X-API-Key  :value"])
        headers, _ = _parse_auth_args(args)
        assert "X-API-Key" in headers

    def test_malformed_header_no_colon_exits(self):
        args = make_args(auth_headers=["BadHeaderWithoutColon"])
        with pytest.raises(SystemExit) as exc_info:
            _parse_auth_args(args)
        assert exc_info.value.code == 1

    def test_empty_header_name_exits(self):
        args = make_args(auth_headers=[":value-only"])
        with pytest.raises(SystemExit) as exc_info:
            _parse_auth_args(args)
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# _parse_auth_args — --auth-cookie
# ---------------------------------------------------------------------------

class TestAuthCookie:
    def test_single_cookie_parsed(self):
        args = make_args(auth_cookies=["sessionid=abc123"])
        _, cookies = _parse_auth_args(args)
        assert cookies["sessionid"] == "abc123"

    def test_multiple_cookies_all_collected(self):
        args = make_args(auth_cookies=["sessionid=abc", "csrftoken=xyz"])
        _, cookies = _parse_auth_args(args)
        assert cookies["sessionid"] == "abc"
        assert cookies["csrftoken"] == "xyz"

    def test_cookie_value_with_equals_preserved(self):
        """Cookie values can contain '=' (base64-encoded values)."""
        args = make_args(auth_cookies=["token=base64=="])
        _, cookies = _parse_auth_args(args)
        assert cookies["token"] == "base64=="

    def test_malformed_cookie_no_equals_exits(self):
        args = make_args(auth_cookies=["nocookievalue"])
        with pytest.raises(SystemExit) as exc_info:
            _parse_auth_args(args)
        assert exc_info.value.code == 1

    def test_empty_cookie_name_exits(self):
        args = make_args(auth_cookies=["=value-only"])
        with pytest.raises(SystemExit) as exc_info:
            _parse_auth_args(args)
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# Combined flags
# ---------------------------------------------------------------------------

class TestAuthCombined:
    def test_all_three_flags_together(self):
        args = make_args(
            auth_bearer="tok",
            auth_headers=["X-API-Key:k1"],
            auth_cookies=["sessionid=s1"],
        )
        headers, cookies = _parse_auth_args(args)
        assert headers["Authorization"] == "Bearer tok"
        assert headers["X-API-Key"] == "k1"
        assert cookies["sessionid"] == "s1"

    def test_bearer_does_not_bleed_into_cookies(self):
        args = make_args(auth_bearer="tok")
        headers, cookies = _parse_auth_args(args)
        assert cookies == {}

    def test_empty_flags_produce_empty_dicts(self):
        args = make_args()
        headers, cookies = _parse_auth_args(args)
        assert headers == {}
        assert cookies == {}


# ---------------------------------------------------------------------------
# Config integration — headers flow through to PhantomConfig
# ---------------------------------------------------------------------------

class TestAuthConfigIntegration:
    def test_custom_headers_stored_in_config(self):
        config = make_config(custom_headers={"X-API-Key": "secret"})
        assert config.custom_headers["X-API-Key"] == "secret"

    def test_session_cookies_stored_in_config(self):
        config = make_config(session_cookies={"sessionid": "abc"})
        assert config.session_cookies["sessionid"] == "abc"

    def test_config_headers_property_merges_auth_and_user_agent(self):
        """config.headers must include both User-Agent and custom auth headers."""
        config = make_config(custom_headers={"Authorization": "Bearer tok"})
        headers = config.headers
        assert "User-Agent" in headers
        assert headers["Authorization"] == "Bearer tok"

    def test_auth_header_overrides_default(self):
        """A custom User-Agent via --auth-header should override the default."""
        config = make_config(custom_headers={"User-Agent": "PhantomScanner/1.0"})
        assert config.headers["User-Agent"] == "PhantomScanner/1.0"

    def test_multiple_custom_headers_all_present(self):
        config = make_config(custom_headers={
            "Authorization": "Bearer tok",
            "X-Tenant-ID": "acme",
        })
        headers = config.headers
        assert headers["Authorization"] == "Bearer tok"
        assert headers["X-Tenant-ID"] == "acme"


# ---------------------------------------------------------------------------
# CLI flag presence — verify argparse wiring
# ---------------------------------------------------------------------------

class TestCLIFlagWiring:
    """Smoke-test that the flags exist in the parser and have correct dest."""

    def _parse(self, *argv):
        return build_parser().parse_args(["scan", "https://example.com", *argv])

    def test_auth_bearer_flag_exists(self):
        args = self._parse("--auth-bearer", "mytoken")
        assert args.auth_bearer == "mytoken"

    def test_auth_header_flag_exists_and_appends(self):
        args = self._parse("--auth-header", "X-A:1", "--auth-header", "X-B:2")
        assert "X-A:1" in args.auth_headers
        assert "X-B:2" in args.auth_headers

    def test_auth_cookie_flag_exists_and_appends(self):
        args = self._parse("--auth-cookie", "a=1", "--auth-cookie", "b=2")
        assert "a=1" in args.auth_cookies
        assert "b=2" in args.auth_cookies

    def test_no_auth_flags_gives_empty_defaults(self):
        args = self._parse()
        assert args.auth_bearer == ""
        assert args.auth_headers == []
        assert args.auth_cookies == []

    def test_discover_command_also_has_auth_flags(self):
        """Auth flags must be available on 'discover' too, not just 'scan'."""
        args = build_parser().parse_args([
            "discover", "https://example.com",
            "--auth-bearer", "tok",
        ])
        assert args.auth_bearer == "tok"