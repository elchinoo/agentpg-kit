"""Guard for user-supplied URLs the server will call (LLM providers, webhooks).

Blocks loopback, private, link-local (cloud metadata), reserved, carrier-grade-NAT, benchmark and documentation addresses, the
IPv6 forms that embed an IPv4 address (IPv4-mapped, IPv4-compatible, NAT64, 6to4, Teredo) when the embedded address is not public,
site-local IPv6, URLs with embedded credentials, and plain http to non-local hosts. An operator may allow private/loopback targets
(a local model server, a webhook receiver) with an environment variable; link-local is always blocked.

The hostname is resolved ONCE, here. `resolve(url)` returns a `Resolved` that carries the validated IP address; the caller
connects to that literal address (`Resolved.request_args()` gives the URL, Host header and TLS server name to use), so a hostile
DNS server cannot answer differently at connect time. Redirects are never followed by the kit's clients.
"""
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import env_bool


class UnsafeURL(ValueError):
    pass


def _nets(*cidrs: str):
    return tuple(ipaddress.ip_network(c) for c in cidrs)


# Not reliably classified by `ipaddress.is_global` across Python versions (3.13 calls several of the IPv6 ones global).
_BLOCKED_V4 = _nets("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
                    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")
_BLOCKED_V6 = _nets("::/96", "::1/128", "100::/64", "2001:db8::/32", "3fff::/20", "5f00::/16", "64:ff9b:1::/48", "fc00::/7", "fe80::/10",
                    "fec0::/10", "ff00::/8")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")
_LINK_LOCAL_V4 = ipaddress.ip_network("169.254.0.0/16")


def _embedded(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """Every IPv4 address an IPv6 address can carry (all of them must be public for the address to be public)."""
    packed = ip.packed
    found: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped:
        found.append(ip.ipv4_mapped)
    if ip in _NAT64:
        found.append(ipaddress.IPv4Address(packed[12:]))
    if ip in _SIXTOFOUR:
        found.append(ipaddress.IPv4Address(packed[2:6]))
    if ip in _TEREDO:
        found.append(ipaddress.IPv4Address(packed[4:8]))                                   # the Teredo server
        found.append(ipaddress.IPv4Address(bytes(b ^ 0xFF for b in packed[12:])))          # the client (obfuscated)
    return found


def classify(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """None for a public address, "link-local" for link-local (always refused), "private" for everything else not public."""
    if isinstance(ip, ipaddress.IPv6Address):
        verdicts = [classify(v4) for v4 in _embedded(ip)]
        if ip.is_link_local:
            verdicts.append("link-local")
        if any(ip in n for n in _BLOCKED_V6):
            verdicts.append("private")
        elif not ip.is_global and not (ip in _NAT64 or ip in _SIXTOFOUR or ip in _TEREDO or ip.ipv4_mapped):
            verdicts.append("private")
        return "link-local" if "link-local" in verdicts else ("private" if "private" in verdicts else None)
    if ip in _LINK_LOCAL_V4:
        return "link-local"
    if any(ip in n for n in _BLOCKED_V4) or not ip.is_global:
        return "private"
    return None


@dataclass(frozen=True)
class Resolved:
    url: str                    # normalised base URL (no trailing slash)
    host: str
    port: int
    scheme: str
    ip: str | None              # the validated address to connect to; None means "do not pin" (tests, trusted callers)

    def request_args(self, path: str = "") -> tuple[str, dict[str, str], dict]:
        """(url, headers, extensions) for httpx: the request goes to the literal IP, with the original Host header and the original
        name for TLS server-name indication and certificate verification, so there is no second DNS lookup."""
        full = f"{self.url}{path}"
        if not self.ip:
            return full, {}, {}
        literal = f"[{self.ip}]" if ":" in self.ip else self.ip
        default = 443 if self.scheme == "https" else 80
        parts = urlsplit(full)
        netloc = f"{literal}:{self.port}"
        host_header = self.host if self.port == default else f"{self.host}:{self.port}"
        if ":" in self.host:
            host_header = f"[{self.host}]" + ("" if self.port == default else f":{self.port}")
        url = parts._replace(netloc=netloc).geturl()
        ext = {"sni_hostname": self.host} if self.scheme == "https" else {}
        return url, {"Host": host_header}, ext


class NetGuard:
    def __init__(self, allow_private_env: str):
        self.allow_private_env = allow_private_env

    def resolve(self, url: str) -> Resolved:
        """Validate a base URL, resolve its host once and return the pinned target. Raises UnsafeURL."""
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
            port = parts.port or (443 if parts.scheme == "https" else 80)
            infos = socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, ValueError) as exc:
            raise UnsafeURL(f"cannot resolve host {parts.hostname!r}") from exc
        if not infos:
            raise UnsafeURL(f"cannot resolve host {parts.hostname!r}")
        allow = env_bool(self.allow_private_env)
        local = False
        pinned: str | None = None
        for info in infos:                       # every answer must be acceptable, so a mixed answer cannot slip a bad one in
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            kind = classify(ip)
            if kind == "link-local":
                raise UnsafeURL("link-local addresses (including cloud metadata services) are not allowed")
            if kind:
                if not allow:
                    raise UnsafeURL(f"that address is private or local; set {self.allow_private_env}=true on the server to allow it")
                local = True
            pinned = pinned or str(ip)
        if parts.scheme == "http" and not local:
            raise UnsafeURL("plain http is only allowed for local servers; use https://")
        return Resolved(url.rstrip("/"), parts.hostname, port, parts.scheme, pinned)

    def check(self, url: str) -> str:
        """Validate and normalise a base URL (no trailing slash). Raises UnsafeURL. Use `resolve` to also pin the connection."""
        return self.resolve(url).url
