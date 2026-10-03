from unittest.mock import patch

import pytest
import requests

from app.core.outbound import _PinnedHTTPSAdapter, integration_request, validate_outbound_url


@pytest.fixture(autouse=True)
def public_policy(monkeypatch):
    monkeypatch.setenv("CRISP_ENV", "production")
    monkeypatch.delenv("CRISP_OUTBOUND_ORIGINS", raising=False)
    monkeypatch.delenv("CRISP_INTEGRATION_CA_BUNDLE", raising=False)


def addresses(*ips):
    return [(2 if ":" not in ip else 10, 1, 6, "", (ip, 443)) for ip in ips]


def test_new_public_endpoint_needs_no_administrator_approval():
    with patch("socket.getaddrinfo", return_value=addresses("8.8.8.8")):
        assert validate_outbound_url("https://judge-wazuh.example:55000")


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "168.63.129.16", "::1", "fc00::1", "::ffff:127.0.0.1"])
def test_non_public_destinations_remain_blocked(ip, monkeypatch):
    monkeypatch.setenv("CRISP_ALLOW_PRIVATE_OUTBOUND", "1")
    with patch("socket.getaddrinfo", return_value=addresses(ip)), patch("requests.Session.request") as request:
        with pytest.raises(ValueError):
            integration_request("post", "https://judge-wazuh.example", auth=("user", "secret"))
        request.assert_not_called()


def test_mixed_public_and_private_dns_is_rejected():
    with patch("socket.getaddrinfo", return_value=addresses("8.8.8.8", "10.0.0.1")):
        with pytest.raises(ValueError):
            validate_outbound_url("https://judge-wazuh.example")


def test_pinned_pool_preserves_hostname_and_certificate_verification():
    prepared = requests.Request("GET", "https://judge-wazuh.example:55000/agents").prepare()
    adapter = _PinnedHTTPSAdapter("judge-wazuh.example", "8.8.8.8")
    with patch.object(adapter.poolmanager, "connection_from_host") as pool:
        adapter.get_connection_with_tls_context(prepared, True)
    assert pool.call_args.kwargs["host"] == "8.8.8.8"
    assert pool.call_args.kwargs["port"] == 55000
    tls = pool.call_args.kwargs["pool_kwargs"]
    assert tls["server_hostname"] == "judge-wazuh.example"
    assert tls["assert_hostname"] == "judge-wazuh.example"
    assert tls["cert_reqs"] == "CERT_REQUIRED"


def test_transport_resolves_once_disables_proxies_and_redirects():
    response = requests.Response()
    response.status_code = 302
    response._content = b'{}'
    response._content_consumed = True
    with patch("socket.getaddrinfo", return_value=addresses("8.8.8.8")) as dns, \
         patch("requests.Session.request", autospec=True, return_value=response) as request, \
         patch("requests.Session.mount") as mount:
        result = integration_request("post", "https://judge-wazuh.example:55000/auth", auth=("user", "secret"), verify=False, allow_redirects=True)
    assert result.status_code == 302
    dns.assert_called_once()
    assert isinstance(mount.call_args.args[1], _PinnedHTTPSAdapter)
    assert request.call_args.kwargs["verify"] is True
    assert request.call_args.kwargs["allow_redirects"] is False
    assert request.call_args.kwargs["proxies"] == {}
    assert request.call_args.kwargs["headers"]["Host"] == "judge-wazuh.example:55000"
    assert request.call_args.args[0].trust_env is False


def test_ai_provider_policy_remains_restricted():
    with pytest.raises(ValueError, match="allowlist"):
        validate_outbound_url("https://unknown-provider.example", provider=True)


def test_large_response_is_rejected_and_closed():
    from unittest.mock import Mock
    response = Mock()
    response.iter_content.return_value = [b'x' * (8 * 1024 * 1024 + 1)]
    with patch("socket.getaddrinfo", return_value=addresses("8.8.8.8")), \
         patch("requests.Session.request", return_value=response):
        with pytest.raises(requests.exceptions.ConnectionError, match="size limit"):
            integration_request("get", "https://judge-wazuh.example/agents")
    response.close.assert_called_once()
