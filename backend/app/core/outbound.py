"""Public HTTPS integration validation and DNS-pinned credential transport."""
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


def _validated_target(url, provider=False):
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
        return parts, None
    if parts.scheme != "https":
        raise ValueError("Production integrations require HTTPS")
    host = parts.hostname.lower().rstrip(".")
    formatted_host = f"[{host}]" if ":" in host else host
    origin = f"https://{formatted_host}" + (f":{port}" if port and port != 443 else "")
    if provider:
        allowed = {v.strip().lower().rstrip("/") for v in os.getenv("CRISP_OUTBOUND_ORIGINS", "").split(",") if v.strip()}
        allowed |= PROVIDER_ORIGINS
        if origin not in allowed:
            raise ValueError("AI provider origin is not in the server's outbound allowlist")
    try:
        addresses = {ipaddress.ip_address(r[4][0]) for r in socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)}
    except (OSError, ValueError):
        raise ValueError("Unable to resolve integration host") from None
    if not addresses:
        raise ValueError("Unable to resolve integration host")
    for address in addresses:
        effective = getattr(address, "ipv4_mapped", None) or address
        if effective == ipaddress.ip_address("168.63.129.16"):
            raise ValueError("Cloud platform service addresses are forbidden for integrations")
        if effective.is_loopback or effective.is_link_local or effective.is_unspecified or effective.is_multicast or effective.is_reserved:
            raise ValueError("Integration host resolves to a forbidden address")
        if not effective.is_global:
            raise ValueError("Integration endpoint must resolve only to public internet addresses")
        if isinstance(address, ipaddress.IPv6Address) and (
                address.sixtofour is not None or address.teredo is not None or
                address in ipaddress.ip_network("64:ff9b::/96") or
                address in ipaddress.ip_network("64:ff9b:1::/48")):
            raise ValueError("IPv6 transition addresses are not supported for integrations")
    return parts, sorted(addresses, key=lambda address: (address.version, int(address)))[0]


def validate_outbound_url(url, provider=False):
    _validated_target(url, provider=provider)
    return url


class _PinnedHTTPSAdapter(requests.adapters.HTTPAdapter):
    """Connect to the checked address while verifying the original TLS hostname."""

    def __init__(self, hostname, address):
        self.hostname = hostname
        self.address = str(address)
        super().__init__(max_retries=0)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        host_params, pool_kwargs = self.build_connection_pool_key_attributes(request, verify, cert)
        host_params["host"] = self.address
        pool_kwargs["server_hostname"] = self.hostname
        pool_kwargs["assert_hostname"] = self.hostname
        return self.poolmanager.connection_from_host(**host_params, pool_kwargs=pool_kwargs)


def integration_request(method, url, **kwargs):
    parts, address = _validated_target(url)
    # Never forward integration credentials to a redirect target. Production TLS
    # uses system roots or an administrator-supplied CA bundle, never verify=False.
    kwargs["allow_redirects"] = False
    kwargs["verify"] = os.getenv("CRISP_INTEGRATION_CA_BUNDLE") or True
    if not production():
        return getattr(requests, method.lower())(url, **kwargs)
    # Disable environment proxies/netrc and prevent a second DNS lookup from
    # changing the destination after validation. Retain SNI, Host and TLS checks.
    with requests.Session() as session:
        session.trust_env = False
        session.mount("https://", _PinnedHTTPSAdapter(parts.hostname, address))
        kwargs["proxies"] = {}
        kwargs["headers"] = {**kwargs.get("headers", {}), "Host": parts.netloc}
        kwargs.setdefault("timeout", 10)
        kwargs["stream"] = True
        response = session.request(method, url, **kwargs)
        try:
            chunks = []
            size = 0
            for chunk in response.iter_content(chunk_size=65536):
                size += len(chunk)
                if size > 8 * 1024 * 1024:
                    raise requests.exceptions.ConnectionError("Integration response exceeds the size limit")
                chunks.append(chunk)
            response._content = b"".join(chunks)
            response._content_consumed = True
            return response
        finally:
            response.close()
