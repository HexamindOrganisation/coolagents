"""Unit tests for the request -> tool-call arg mapping."""

from __future__ import annotations

import pytest

from hexgate.egress.model import connect_to_args, http_to_args, split_authority


def test_connect_to_args() -> None:
    assert connect_to_args("api.github.com", 443) == {
        "method": "CONNECT",
        "scheme": "https",
        "host": "api.github.com",
        "port": 443,
        "url": "https://api.github.com:443",
    }


def test_http_to_args_defaults_port_80() -> None:
    args = http_to_args("GET", "http://example.com/path?q=1")
    assert args["method"] == "GET"
    assert args["scheme"] == "http"
    assert args["host"] == "example.com"
    assert args["port"] == 80
    assert args["path"] == "/path"
    assert args["url"] == "http://example.com/path?q=1"


def test_http_to_args_explicit_port() -> None:
    args = http_to_args("POST", "http://example.com:8080/x")
    assert args["port"] == 8080


def test_http_to_args_root_path() -> None:
    assert http_to_args("GET", "http://example.com")["path"] == "/"


def test_http_to_args_keeps_query() -> None:
    args = http_to_args("GET", "http://example.com/search?q=hello&n=2")
    assert args["path"] == "/search"
    assert args["query"] == "q=hello&n=2"


def test_connect_to_args_brackets_ipv6_in_url() -> None:
    args = connect_to_args("2606:4700::1", 443)
    assert args["host"] == "2606:4700::1"  # host itself is bracket-free
    assert args["url"] == "https://[2606:4700::1]:443"


def test_split_authority_with_port() -> None:
    assert split_authority("api.github.com:443") == ("api.github.com", 443)


def test_split_authority_defaults_443() -> None:
    assert split_authority("api.github.com") == ("api.github.com", 443)


def test_split_authority_rejects_non_integer_port() -> None:
    with pytest.raises(ValueError):
        split_authority("host:not-a-port")


def test_split_authority_ipv6_with_port() -> None:
    assert split_authority("[2606:4700::1]:443") == ("2606:4700::1", 443)


def test_split_authority_ipv6_without_port() -> None:
    assert split_authority("[::1]") == ("::1", 443)


def test_split_authority_ipv6_unterminated_bracket_raises() -> None:
    with pytest.raises(ValueError):
        split_authority("[::1")
