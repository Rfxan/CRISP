import json
from unittest.mock import patch

import pytest

from app.ai import vendor_mapping
from app.connectors.sniffer import detect_structure
from test_audit_regressions import isolated_app


def sample_export():
    return json.dumps({"vulnerabilities": [{
        "host": "private-host.internal", "asset_token": "PRIVATE-ASSET-123", "severity": "critical",
        "title": "", "definition": {"title": "Private finding", "description": "PRIVATE-DESCRIPTION"},
        "cvss_scores": {"cvss_3_1": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
        "cwe": 502, "references": [{"name": "CVE-2021-44228"}],
        "request": {"body": "PRIVATE-REQUEST-CREDENTIAL", "url": "https://private-host.internal/login"},
    }]}).encode()


def proposed_mapping(**changes):
    return {"asset_id": "host", "cve_id": "references.name", "cvss": "cvss_scores.cvss_3_1.score",
            "severity": "severity", "port": None, "issue_type": "definition.title", **changes}


def ai_response(mapping=None):
    return {"provider": "openai", "model": "validation-model", "latency_ms": 12,
            "answer": json.dumps({"field_mapping": mapping or proposed_mapping()})}


def model_config(**changes):
    return {"provider": "openai", "model": "validation-model", "api_key": "PRIVATE-TEST-KEY",
            "enabled": True, **changes}


def test_ai_uses_configured_provider_without_sending_scan_values():
    inspection = detect_structure(sample_export(), "json")
    with patch.object(vendor_mapping.llm_config_store, "get_config", return_value=model_config()), \
         patch.object(vendor_mapping.llm_service, "generate_response", return_value=ai_response()) as generate:
        result = vendor_mapping.suggest_mapping_with_ai(inspection)
    assert result["source"] == "llm"
    assert result["provider"] == "openai" and result["model"] == "validation-model"
    assert result["suggested_mapping"]["cvss"] == "cvss_scores.cvss_3_1.score"
    prompt, system, config = generate.call_args.args
    sent = json.loads(prompt)
    assert set(sent) == {"format", "detected_record_path", "record_count_sample", "available_fields", "field_profiles"}
    assert sent["field_profiles"]["references.name"]["cve_matches"] == 1
    for secret in ("private-host.internal", "PRIVATE-ASSET", "PRIVATE-DESCRIPTION", "PRIVATE-REQUEST", "PRIVATE-TEST-KEY", "CVE-2021-44228"):
        assert secret not in prompt + system
    assert config["api_key"] == "PRIVATE-TEST-KEY"  # It is used for authentication, not placed in the prompt.
    assert generate.call_args.kwargs == {"timeout": 20.0, "max_retries": 0}


@pytest.mark.parametrize("changes", [
    {"asset_id": "invented.hostname"},
    {"cvss": "cvss_scores.cvss_3_1.vector"},
    {"cve_id": "cwe"},
    {"severity": "cvss_scores.cvss_3_1.score"},
    {"cvss": "cvss_scores"},
    {"port": 443},
    {"unsupported_field": "host"},
])
def test_ai_output_is_rejected_when_paths_or_types_are_invalid(changes):
    inspection = detect_structure(sample_export(), "json")
    with patch.object(vendor_mapping.llm_config_store, "get_config", return_value=model_config()), \
         patch.object(vendor_mapping.llm_service, "generate_response", return_value=ai_response(proposed_mapping(**changes))):
        with pytest.raises(ValueError):
            vendor_mapping.suggest_mapping_with_ai(inspection)


@pytest.mark.parametrize("changes", [{"api_key": ""}, {"enabled": False}])
def test_no_enabled_model_does_not_call_a_provider(changes):
    inspection = detect_structure(sample_export(), "json")
    with patch.object(vendor_mapping.llm_config_store, "get_config", return_value=model_config(**changes)), \
         patch.object(vendor_mapping.llm_service, "generate_response") as generate:
        with pytest.raises(vendor_mapping.MappingAIUnavailable):
            vendor_mapping.suggest_mapping_with_ai(inspection)
        generate.assert_not_called()


def test_ai_endpoint_returns_real_provider_metadata_and_mapping(isolated_app):
    client = isolated_app
    saved = client.post("/api/ai/config", json={"provider": "openai", "model": "validation-model",
                                               "api_key": "PRIVATE-TEST-KEY", "enabled": True})
    assert saved.status_code == 200, saved.text
    with patch.object(vendor_mapping.llm_service, "generate_response", return_value=ai_response()) as generate:
        response = client.post("/api/vendors/suggest-ai", files={"file": ("scanner.json", sample_export(), "application/json")})
    assert response.status_code == 200, response.text
    assert response.json()["source"] == "llm"
    assert generate.call_args.args[2]["api_key"] == "PRIVATE-TEST-KEY"
    assert "PRIVATE-TEST-KEY" not in response.text
    inspection = client.post("/api/vendors/inspect", files={"file": ("scanner.json", sample_export())}).json()
    preview = client.post("/api/vendors/preview", files={"file": ("scanner.json", sample_export())}, data={
        "format": "json", "record_path": inspection["detected_record_path"],
        "field_mapping": json.dumps(response.json()["suggested_mapping"])})
    assert preview.status_code == 200, preview.text
    findings = preview.json()["findings"]
    assert len(findings) == 1 and findings[0]["cvss"] == 9.8 and findings[0]["cve_id"] == "CVE-2021-44228"


def test_guest_ai_requires_its_own_model_configuration(isolated_app, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "PRIVATE-OWNER-KEY")
    with patch.object(vendor_mapping.llm_service, "generate_response") as generate:
        response = isolated_app.post("/api/vendors/suggest-ai", files={"file": ("scanner.json", sample_export())})
    assert response.status_code == 409, response.text
    assert "AI Model Settings" in response.json()["detail"]
    generate.assert_not_called()


@pytest.mark.parametrize("failure", [RuntimeError("PRIVATE-PROVIDER-SECRET"), None])
def test_provider_failure_or_malformed_output_does_not_return_fallback_as_ai(isolated_app, failure):
    with patch.object(vendor_mapping.llm_config_store, "get_config", return_value=model_config()), \
         patch.object(vendor_mapping.llm_service, "generate_response", side_effect=failure,
                      return_value={"answer": "Not JSON: PRIVATE-PROVIDER-SECRET"}):
        response = isolated_app.post("/api/vendors/suggest-ai", files={"file": ("scanner.json", sample_export())})
    assert response.status_code == 502, response.text
    assert "PRIVATE-PROVIDER-SECRET" not in response.text
    assert "suggested_mapping" not in response.json()


def test_generic_preview_preserves_information_and_skips_unknown_severity():
    from app.connectors.generic import GenericVendorConnector
    data = json.dumps([{"host": "192.0.2.1", "severity": "information", "title": "Info finding"},
                       {"host": "192.0.2.1", "severity": "not-a-severity", "title": "Invalid finding"}]).encode()
    parsed = GenericVendorConnector({"format": "json", "record_path": "root", "field_mapping": {
        "asset_id": "host", "severity": "severity", "issue_type": "title"}}).parse(data)
    assert parsed["skipped"] == 1
    assert len(parsed["findings"]) == 1 and parsed["findings"][0]["severity"] == "Info"


def test_existing_provider_sdk_sends_validated_schema_and_reads_model_completion():
    import httpx
    from openai import OpenAI
    from app.ai.llm_service import LLMService

    requests_seen = []
    def provider_reply(request):
        body = json.loads(request.content)
        requests_seen.append(body)
        assert body["model"] == "validation-model"
        assert json.loads(body["messages"][1]["content"])["detected_record_path"] == "vulnerabilities"
        assert "PRIVATE-REQUEST-CREDENTIAL" not in request.content.decode()
        return httpx.Response(200, json={"id": "validation-completion", "object": "chat.completion",
            "created": 0, "model": "validation-model", "choices": [{"index": 0,
            "message": {"role": "assistant", "content": ai_response()["answer"]}, "finish_reason": "stop"}]})

    client = OpenAI(api_key="test-only-controlled-key", base_url="https://api.openai.com/v1",
                    http_client=httpx.Client(transport=httpx.MockTransport(provider_reply)), max_retries=0)
    try:
        with patch.object(vendor_mapping.llm_config_store, "get_config", return_value=model_config()), \
             patch.object(LLMService, "_get_client_for_provider", return_value=client):
            result = vendor_mapping.suggest_mapping_with_ai(detect_structure(sample_export(), "json"))
        assert len(requests_seen) == 1
        assert result["source"] == "llm" and result["model"] == "validation-model"
        assert result["suggested_mapping"]["cvss"] == "cvss_scores.cvss_3_1.score"
    finally:
        client.close()
