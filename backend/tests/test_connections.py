"""
Pytest test suite for CRISP Connections Feature.
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from fastapi.testclient import TestClient

from app.main import app, sync_telemetry_cycle
from app.core.security import encrypt_credential, decrypt_credential
from app.core.connections_store import connections_store
from app.api.routes import store

client = TestClient(app)

class MockWazuhHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/security/user/authenticate":
            auth_header = self.headers.get("Authorization", "")
            if auth_header == "Basic d2F6dWgtd3VpOnNlY3JldDEyMw==":  # wazuh-wui:secret123
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"data": {"token": "jwt-token-123"}}).encode("utf-8"))
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": 401, "message": "Invalid Wazuh user or password"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        auth_header = self.headers.get("Authorization", "")
        if auth_header != "Bearer jwt-token-123":
            self.send_response(401)
            self.end_headers()
            return

        if "/agents" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "data": {
                    "total_affected_items": 10,
                    "affected_items": [{"id": f"{i:03d}", "status": "active" if i <= 9 else "disconnected"} for i in range(1, 11)]
                }
            }).encode("utf-8"))
        elif "/alerts" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "data": {"total_affected_items": 15, "affected_items": []}
            }).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def test_connections_lifecycle_and_security():
    # Start mock server
    mock_server = HTTPServer(("127.0.0.1", 55002), MockWazuhHandler)
    t = threading.Thread(target=mock_server.serve_forever, daemon=True)
    t.start()

    # Part 1: Encryption
    token = "FernetSecretTest2026!"
    enc = encrypt_credential(token)
    assert decrypt_credential(enc) == token

    # Part 3: Test valid connection
    valid_payload = {
        "base_url": "http://127.0.0.1:55002",
        "username": "wazuh-wui",
        "password": "secret123"
    }
    resp = client.post("/api/connections/siem/test", json=valid_payload)
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    assert "Found 10 agents (9 active" in resp.json()["detail"]

    # Deliberate failure test
    bad_payload = {
        "base_url": "http://127.0.0.1:55002",
        "username": "wazuh-wui",
        "password": "WrongPassword!"
    }
    resp_bad = client.post("/api/connections/siem/test", json=bad_payload)
    assert resp_bad.status_code == 200
    assert resp_bad.json()["success"] is False
    assert "401" in resp_bad.json()["detail"]

    # Save connection
    resp_save = client.post("/api/connections/siem/save", json=valid_payload)
    assert resp_save.status_code == 200
    assert resp_save.json()["status"] == "SAVED"
    assert "password" not in resp_save.json()["connection"]

    # GET /api/connections
    resp_get = client.get("/api/connections")
    assert resp_get.status_code == 200
    data = resp_get.json()
    assert data["siem"]["connected"] is True
    assert "password" not in json.dumps(data).lower()

    # Scheduler cycle
    sync_telemetry_cycle()
    ctrl_edr = next((c for c in store.current_snapshot.get("control_state", []) if c.get("control_id") == "CTRL-EDR-01"), None)
    assert ctrl_edr is not None
    assert ctrl_edr["coverage_pct"] == 90.0
    assert "Wazuh Live API (9/10 endpoints)" in ctrl_edr["evidence_ref"]

    # Delete connection
    resp_del = client.delete("/api/connections/siem")
    assert resp_del.status_code == 200
    assert resp_del.json()["status"] == "REMOVED"
