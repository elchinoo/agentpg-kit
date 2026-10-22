"""Guard for user-supplied URLs the server will call (LLM providers, webhooks).

Blocks loopback, private, link-local (cloud metadata), reserved and carrier-grade-NAT addresses, URLs with embedded
credentials, and plain http to non-local hosts. An operator may allow private/loopback targets (a local model server, a
webhook receiver) with an environment variable; link-local is always blocked.

Limitation: the hostname is resolved here and again by the HTTP client, so a hostile DNS server could answer differently the
second time. Redirects are never followed by the kit's clients, which closes the common route.
"""
import ipaddress
import socket
from urllib.parse import urlsplit

from .config import env_bool


class UnsafeURL(ValueError):
    pass


class NetGuard:
    def __init__(self, allow_private_env: str):
        self.allow_private_env = allow_private_env

    def check(self, url: str) -> str:
        """Validate and normalise a base URL (no trailing slash). Raises UnsafeURL."""
        url = (url or "").strip()
        if not url or len(url) > 300:
            raise UnsafeURL("URL is required (max 300 characters)")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise UnsafeURL("URL must start with https:// (or http:// for an allowed local server)")
        if parts.username or parts.password:
            raise UnsafeURL("credentials must not be embedded in the URL")
        if parts.query or parts.fragment:
            raise UnsafeURL("URL must not contain a query string or fragment")
        try:
            infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise UnsafeURL(f"cannot resolve host {parts.hostname!r}") from exc
        allow = env_bool(self.allow_private_env)
        local = False
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            if ip.is_link_local:
                raise UnsafeURL("link-local addresses (including cloud metadata services) are not allowed")
            if not ip.is_global:
                if not allow:
                    raise UnsafeURL(f"that address is private or local; set {self.allow_private_env}=true on the server to allow it")
                local = True
        if parts.scheme == "http" and not local:
            raise UnsafeURL("plain http is only allowed for local servers; use https://")
        return url.rstrip("/")
