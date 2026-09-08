from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.types import ChainmailContext, ChainmailResult

HTTP_FETCH_PRIVATE_RANGES = (
    "127.",
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "localhost",
    "0.0.0.0",
    "::1",
    "fe80::",
)


@dataclass(slots=True)
class HttpFetchOptions:
    method: str | None = None
    headers: dict[str, str] | None = None
    timeout_ms: float | None = None
    validate_response: Callable[[int, Any], bool] | None = None
    on_success: Callable[[ChainmailContext, Any], None] | None = None
    on_error: Callable[[ChainmailContext, str], None] | None = None
    allowed_hosts: list[str] | None = None
    max_response_size: int | None = None


def _httpx_available() -> bool:
    try:
        import httpx  # noqa: F401
    except ImportError:
        return False
    return True


def http_fetch(url: str, options: HttpFetchOptions | None = None) -> Rivet:
    opts = options or HttpFetchOptions()
    method = (opts.method or "POST").upper()
    headers = dict(opts.headers or {})
    if not headers:
        headers["Content-Type"] = "application/json"
    timeout_ms = 5000.0 if opts.timeout_ms is None else float(opts.timeout_ms)
    allowed_hosts = opts.allowed_hosts or []
    max_response_size = 1024 * 1024 if opts.max_response_size is None else opts.max_response_size

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        if not _httpx_available():
            context.flags.add(SecurityFlags.HTTP_ERROR)
            context.metadata["http_error"] = "http feature disabled"
            return nxt(context)

        import httpx

        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        hostname = (parsed.hostname or "").lower()
        if not scheme or not hostname:
            context.flags.add(SecurityFlags.HTTP_ERROR)
            apply_threat_penalty(context, ThreatLevel.HIGH)
            context.metadata["http_error"] = "Invalid URL format"
            return nxt(context)
        if any(hostname.startswith(prefix) for prefix in HTTP_FETCH_PRIVATE_RANGES):
            context.flags.add(SecurityFlags.HTTP_ERROR)
            apply_threat_penalty(context, ThreatLevel.HIGH)
            context.metadata["http_error"] = "Private/local IP addresses are not allowed"
            return nxt(context)
        if allowed_hosts and hostname not in allowed_hosts:
            context.flags.add(SecurityFlags.HTTP_ERROR)
            apply_threat_penalty(context, ThreatLevel.HIGH)
            context.metadata["http_error"] = f"Host {hostname} is not in allowlist"
            return nxt(context)
        if scheme not in {"http", "https"}:
            context.flags.add(SecurityFlags.HTTP_ERROR)
            apply_threat_penalty(context, ThreatLevel.HIGH)
            context.metadata["http_error"] = "Only HTTP/HTTPS protocols are allowed"
            return nxt(context)

        try:
            with httpx.Client(timeout=timeout_ms / 1000.0) as client:
                body = {"input": context.sanitized}
                if method == "GET":
                    response = client.get(url, headers=headers)
                elif method == "PUT":
                    response = client.put(url, headers=headers, json=body)
                elif method == "PATCH":
                    response = client.patch(url, headers=headers, json=body)
                elif method == "DELETE":
                    response = client.delete(url, headers=headers)
                else:
                    response = client.post(url, headers=headers, json=body)
        except httpx.TimeoutException:
            context.flags.add(SecurityFlags.HTTP_TIMEOUT)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)
            context.metadata["http_error"] = f"Request timed out after {int(timeout_ms)}ms"
            if opts.on_error:
                opts.on_error(context, context.metadata["http_error"])
            return nxt(context)
        except Exception as exc:
            context.flags.add(SecurityFlags.HTTP_ERROR)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)
            context.metadata["http_error"] = str(exc)
            if opts.on_error:
                opts.on_error(context, str(exc))
            return nxt(context)

        if not (200 <= response.status_code < 300):
            msg = f"HTTP {response.status_code}"
            context.flags.add(SecurityFlags.HTTP_ERROR)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)
            context.metadata["http_error"] = msg
            if opts.on_error:
                opts.on_error(context, msg)
            return nxt(context)

        content_length = response.headers.get("content-length")
        if content_length and int(content_length) > max_response_size:
            context.flags.add(SecurityFlags.HTTP_ERROR)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)
            context.metadata["http_error"] = (
                f"Response size {content_length} exceeds limit {max_response_size}"
            )
            return nxt(context)

        try:
            data = response.json()
        except Exception as exc:
            context.flags.add(SecurityFlags.HTTP_ERROR)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)
            context.metadata["http_error"] = str(exc)
            if opts.on_error:
                opts.on_error(context, str(exc))
            return nxt(context)

        if opts.validate_response and not opts.validate_response(response.status_code, data):
            context.flags.add(SecurityFlags.HTTP_VALIDATION_FAILED)
            apply_threat_penalty(context, ThreatLevel.HIGH)
            context.metadata["http_validation_error"] = "Response validation failed"
            return nxt(context)

        context.flags.add(SecurityFlags.HTTP_SUCCESS)
        context.metadata["http_response"] = data
        if opts.on_success:
            opts.on_success(context, data)
        return nxt(context)

    return FnRivet("http_fetch", handler)
