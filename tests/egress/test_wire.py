"""Unit tests for the low-level HTTP wire helpers."""

from __future__ import annotations

from hexgate.egress.wire import parse_request_line, strip_proxy_headers


def test_parse_request_line() -> None:
    assert parse_request_line(b"GET http://h/x HTTP/1.1\r\n") == (
        "GET",
        "http://h/x",
    )


def test_parse_request_line_lowercase_method_upcased() -> None:
    assert parse_request_line(b"connect h:443 HTTP/1.1\r\n")[0] == "CONNECT"


def test_strip_proxy_headers_removes_proxy_scoped() -> None:
    block = (
        b"Host: example.com\r\n"
        b"Proxy-Connection: keep-alive\r\n"
        b"Proxy-Authorization: Basic abc\r\n"
        b"User-Agent: demo\r\n"
        b"\r\n"
    )
    result = strip_proxy_headers(block)
    assert b"proxy-" not in result.lower()
    assert b"Host: example.com" in result
    assert b"User-Agent: demo" in result
    assert result.endswith(b"\r\n\r\n")  # terminating blank line preserved


def test_strip_proxy_headers_noop_when_absent() -> None:
    block = b"Host: example.com\r\nAccept: */*\r\n\r\n"
    assert strip_proxy_headers(block) == block
