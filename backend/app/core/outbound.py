"""Server-controlled egress allowlist for credential-bearing integrations."""
import ipaddress
import os
import socket
from urllib.parse import urlsplit

import requests
from app.core.deployment import production

PROVIDER_ORIGINS = frozenset({
    "https://api.openai.com", "https://api.groq.com", "https://api.deepseek.com",
    "https://api.anthropic.com", "https://generativelanguage.googleapis.com",
})


def validate_outbound_url(url, provider=False):
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError("Invalid integration URL") from None
    if (parts.scheme not in ("http", "https") or not parts.hostname or
            parts.username is not None or parts.password is not None or parts.fragment or
            any(ord(c) < 33 or c == "\\" for c in url)):
        raise ValueError("Integration URL must be HTTP(S), without credentials or fragments")
    if not production():
        return url
    if parts.scheme != "https":
        raise ValueError("Production integrations require HTTPS")
    host = parts.hostname.lower().rstrip(".")
    formatted_host = f"[{host}]" if ":" in host else host
    origin = f"https://{formatted_host}" + (f":{port}" if port and port != 443 else "")
    allowed = {v.strip().lower().rstrip("/") for v in os.getenv("CRISP_OUTBOUND_ORIGINS", "").split(",") if v.strip()}
    if provider:
        allowed |= PROVIDER_ORIGINS
    if origin not in allowed:
        raise ValueError("Integration origin is not in the server's outbound allowlist")
    try:
        addresses = {ipaddress.ip_address(r[4][0]) for r in socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)}
    except (OSError, ValueError):
        raise ValueError("Unable to resolve integration host") from None
    for address in addresses:
        effective = getattr(address, "ipv4_mapped", None) or address
        if effective.is_loopback or effective.is_link_local or effective.is_unspecified or effective.is_multicast or effective.is_reserved:
            raise ValueError("Integration host resolves to a forbidden address")
        if not effective.is_global and os.getenv("CRISP_ALLOW_PRIVATE_OUTBOUND") != "1":
            raise ValueError("Private integration addresses require server approval")
    return url


def integration_request(method, url, **kwargs):
    validate_outbound_url(url)
    # Never forward integration credentials to a redirect target. Production TLS
    # uses system roots or an administrator-supplied CA bundle, never verify=False.
    kwargs["allow_redirects"] = False
    kwargs["verify"] = os.getenv("CRISP_INTEGRATION_CA_BUNDLE") or True
    return getattr(requests, method.lower())(url, **kwargs)
