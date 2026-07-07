"""Strict SSRF egress guard for agent-initiated fetches of EXTERNAL content
(STRIDE I18 — tradecraft crawl).

Unlike ``llm_url_guard`` (which deliberately *allows* loopback / RFC-1918 so the
self-hosted-model feature works), this guard is for fetching untrusted TARGET
web content: it must reject every internal destination. A crawl seed or a
redirect ``Location`` that points at loopback, an RFC-1918 host, link-local /
cloud metadata (``169.254.169.254``), CGNAT, or any non-global address is an
SSRF and is refused.

Reuses ``llm_url_guard._resolve_ips`` for DNS resolution (handles literal IPs,
IPv6 scope ids). The connect-time DNS-rebinding TOCTOU (httpx re-resolves when it
connects) is a documented residual, identical to the I15 remediation stance.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from .llm_url_guard import _resolve_ips, _BLOCKED_HOSTNAMES

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class UnsafeFetchURLError(ValueError):
    """Raised when a URL is not safe to fetch (SSRF into an internal address)."""


def _is_disallowed_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → refuse
    # Judge IPv4-mapped IPv6 (::ffff:10.0.0.1) on the embedded v4 value.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or ip in _CGNAT
    )


def is_safe_fetch_url(url: str) -> bool:
    try:
        assert_safe_fetch_url(url)
        return True
    except UnsafeFetchURLError:
        return False


def assert_safe_fetch_url(url: str) -> None:
    """Raise ``UnsafeFetchURLError`` if ``url`` must not be fetched.

    An unresolvable host is allowed (it cannot be an SSRF into a known internal
    IP, and the request will simply fail); every resolved address must be a
    global/public IP.
    """
    parsed = urlparse((url or "").strip())
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise UnsafeFetchURLError(
            f"refusing to fetch non-http(s) URL (scheme '{scheme or 'none'}')"
        )

    host = parsed.hostname
    if not host:
        raise UnsafeFetchURLError("refusing to fetch URL with no host")

    if host.lower().rstrip(".") in _BLOCKED_HOSTNAMES:
        raise UnsafeFetchURLError("refusing to fetch cloud-metadata host")

    for ip in _resolve_ips(host):
        if _is_disallowed_ip(ip):
            raise UnsafeFetchURLError(
                f"refusing to fetch URL resolving to non-public address {ip} "
                "(loopback / private / link-local / metadata)"
            )
