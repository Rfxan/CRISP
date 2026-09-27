"""
Comprehensive verification script for CRISP Connections Feature.
Tests:
1. Part 1: Fernet credential encryption and decryption (security.py)
2. Part 2: ConnectionsStore persistence, encryption, and public masking (connections_store.py)
3. Part 3: Live API Endpoints (POST /api/connections/siem/test, POST /api/connections/siem/save, GET /api/connections, DELETE)
4. Failure path: Wrong password honesty check
5. Scheduler integration: Automatic telemetry pull updating CTRL-EDR-01 in control_state
"""

import os
import sys
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from fastapi.testclient import TestClient

# Ensure backend is on sys.path
sys.path.insert(0, r"c:\Users\RYAN\Documents\CRISP\backend")

from app.main import app, sync_telemetry_cycle
from app.core.security import encrypt_credential, decrypt_credential
from app.core.connections_store import connections_store
from app.api.routes import store

client = TestClient(app)

# -------------------------------------------------------------
# 1. Mock Wazuh REST API Server on localhost:55001
# -------------------------------------------------------------
class MockWazuhHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/security/user/authenticate":
            auth_header = self.headers.get("Authorization", "")
            # Basic auth: check credentials
            if auth_header == "Basic d2F6dWgtd3VpOnNlY3JldDEyMw==":  # wazuh-wui:secret123
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "data": {"token": "mock-wazuh-jwt-token-xyz"}
                }).encode("utf-8"))
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": 401,
                    "message": "Invalid Wazuh user or password"
                }).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        auth_header = self.headers.get("Authorization", "")
        if auth_header != "Bearer mock-wazuh-jwt-token-xyz":
            self.send_response(401)
            self.end_headers()
            return

        if "/agents" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "data": {
                    "total_affected_items": 16,
                    "affected_items": [{"id": f"{i:03d}", "status": "active" if i <= 14 else "disconnected"} for i in range(1, 17)]
                }
            }).encode("utf-8"))
        elif "/alerts" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "data": {
                    "total_affected_items": 42,
                    "affected_items": [{"rule": {"level": 14, "id": "5710"}} for _ in range(5)]
                }
            }).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Quiet logging

mock_server = HTTPServer(("127.0.0.1", 55001), MockWazuhHandler)
server_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
server_thread.start()
print(">>> Mock Wazuh Server running on http://127.0.0.1:55001")


def run_all_verifications():
    print("=" * 60)
    print("STEP 1: Test Part 1 - Fernet Symmetric Encryption & Decryption")
    print("=" * 60)
    plain = "SuperAdminP@ssw0rd!2026"
    encrypted = encrypt_credential(plain)
    print("Plaintext:           ", plain)
    print("Encrypted Ciphertext:", encrypted)
    decrypted = decrypt_credential(encrypted)
    print("Decrypted Plaintext: ", decrypted)
    assert decrypted == plain, "Decrypted password does not match!"
    print(">>> SUCCESS: Fernet encryption/decryption roundtrip verified!")

    print("\n" + "=" * 60)
    print("STEP 2: Test Part 3 - Test Live Connection with Valid Credentials")
    print("=" * 60)
    test_payload = {
        "base_url": "http://127.0.0.1:55001",
        "username": "wazuh-wui",
        "password": "secret123"
    }
    resp = client.post("/api/connections/siem/test", json=test_payload)
    print("POST /api/connections/siem/test Response Status:", resp.status_code)
    test_data = resp.json()
    print("Response JSON:", json.dumps(test_data, indent=2))
    assert test_data["success"] is True, "Live test should have succeeded!"
    assert "Found 16 agents (14 active" in test_data["detail"]
    print(">>> SUCCESS: Valid connection test succeeded with real agent count!")

    print("\n" + "=" * 60)
    print("STEP 3: Test Failure Path - Wrong Password (Honest Error Reason)")
    print("=" * 60)
    bad_payload = {
        "base_url": "http://127.0.0.1:55001",
        "username": "wazuh-wui",
        "password": "WrongPassword999"
    }
    resp_bad = client.post("/api/connections/siem/test", json=bad_payload)
    print("POST /api/connections/siem/test (Bad Pwd) Status:", resp_bad.status_code)
    bad_data = resp_bad.json()
    print("Response JSON:", json.dumps(bad_data, indent=2))
    assert bad_data["success"] is False, "Bad credentials must return success=False!"
    assert "401" in bad_data["detail"] or "authentication failed" in bad_data["detail"].lower(), "Error must be honest and descriptive!"
    print(">>> SUCCESS: Failure path returned honest error message with HTTP 401!")

    print("\n" + "=" * 60)
    print("STEP 4: Test Save & Connect (POST /api/connections/siem/save)")
    print("=" * 60)
    save_resp = client.post("/api/connections/siem/save", json=test_payload)
    print("POST /api/connections/siem/save Status:", save_resp.status_code)
    save_data = save_resp.json()
    print("Response JSON:", json.dumps(save_data, indent=2))
    assert save_data["status"] == "SAVED"
    assert "password" not in save_data["connection"]
    assert "encrypted_password" not in save_data["connection"]
    print(">>> SUCCESS: Connection saved. Passwords strictly omitted from response!")

    print("\n" + "=" * 60)
    print("STEP 5: Test GET /api/connections (Sanitization Verification)")
    print("=" * 60)
    get_resp = client.get("/api/connections")
    print("GET /api/connections Status:", get_resp.status_code)
    all_conns = get_resp.json()
    print("Response JSON:", json.dumps(all_conns, indent=2))
    assert all_conns["siem"]["connected"] is True
    assert all_conns["siem"]["base_url"] == "http://127.0.0.1:55001"
    # Ensure neither password nor encrypted_password exists anywhere
    raw_text = get_resp.text
    assert "password" not in raw_text.lower(), "Password or encrypted_password leaked in response text!"
    assert "secret123" not in raw_text, "Plaintext password leaked in response text!"
    print(">>> SUCCESS: GET /api/connections shows connected: true and ZERO credential leakage!")

    print("\n" + "=" * 60)
    print("STEP 6: Test Telemetry Scheduler Cycle Pulling from Saved Connection")
    print("=" * 60)
    print("Simulating next scheduled cycle via sync_telemetry_cycle()...")
    sync_telemetry_cycle()

    # Verify CTRL-EDR-01 in control_state updated with real data
    ctrl_edr = next((c for c in store.current_snapshot.get("control_state", []) if c.get("control_id") == "CTRL-EDR-01"), None)
    print("CTRL-EDR-01 Control State:")
    print(json.dumps(ctrl_edr, indent=2))
    assert ctrl_edr is not None
    assert ctrl_edr["coverage_pct"] == 87.5  # 14 / 16 * 100
    assert "Wazuh Live API (14/16 endpoints)" in ctrl_edr["evidence_ref"]
    assert ctrl_edr["is_simulated"] is False
    print(">>> SUCCESS: Scheduler pulled live telemetry from saved connection! CTRL-EDR-01 updated with real data.")

    print("\n" + "=" * 60)
    print("STEP 7: Test DELETE /api/connections/siem (Disconnect)")
    print("=" * 60)
    del_resp = client.delete("/api/connections/siem")
    print("DELETE /api/connections/siem Status:", del_resp.status_code)
    del_data = del_resp.json()
    print("Response JSON:", json.dumps(del_data, indent=2))
    assert del_data["status"] == "REMOVED"

    # Verify GET shows disconnected
    get_after = client.get("/api/connections").json()
    assert get_after["siem"]["connected"] is False
    print(">>> SUCCESS: Connection successfully disconnected and removed.")

    print("\n" + "=" * 60)
    print("ALL 7 VERIFICATION STEPS PASSED PERFECTLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_all_verifications()
