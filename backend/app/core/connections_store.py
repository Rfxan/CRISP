from app.core.tenancy import active, read_document, write_document, principal_context
from app.core.deployment import production
"""
CRISP Connections Store.
Manages persistent storage and lifecycle for SIEM (Wazuh) and IAM (Keycloak) live connections.
Credentials are symmetrically encrypted with Fernet before persisting to connections.json.
Passwords are NEVER exposed over public API endpoints.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from app.core.config import DATA_DIR
from app.core.security import encrypt_credential, decrypt_credential
from app.connectors.wazuh import WazuhConnector
from app.connectors.iam import KeycloakConnector

logger = logging.getLogger(__name__)


def _normalize_category(category: str) -> str:
    """Normalizes category aliases to canonical identifiers: 'siem' or 'iam'."""
    cat = (category or "").strip().lower()
    if cat in ["siem", "edr", "wazuh"]:
        return "siem"
    if cat in ["iam", "keycloak", "idp"]:
        return "iam"
    return cat


def _get_connections_storage_path() -> Path:
    """Returns primary path in DATA_DIR or fallback outside protected Documents folder."""
    primary = DATA_DIR / "connections.json"
    try:
        primary.parent.mkdir(parents=True, exist_ok=True)
        test_file = primary.parent / ".perm_check_conn"
        test_file.write_text("ok")
        test_file.unlink(missing_ok=True)
        return primary
    except Exception:
        try:
            fallback = Path.home() / ".crisp" / "connections.json"
            fallback.parent.mkdir(parents=True, exist_ok=True)
            return fallback
        except Exception:
            return primary


class ConnectionsStore:
    def __init__(self, storage_file: Optional[Path] = None):
        self.file_path = storage_file or _get_connections_storage_path()
        self._ensure_file()

    def _ensure_file(self):
        """Ensures the connections.json file exists and is valid JSON."""
        if active():
            return
        if not self.file_path.exists():
            self._write_file({})
        else:
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if not content:
                        self._write_file({})
            except Exception:
                self._write_file({})

    def _read_file(self) -> Dict[str, Any]:
        """Reads and parses connections.json."""
        if active():
            document = read_document("connections")
            if document is None and not production() and principal_context.get()["tenant"] == "local":
                try:
                    document = json.loads(self.file_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    document = {}
                write_document("connections", document)
            return document or {}
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading {self.file_path}: {e}")
            return {}

    def _write_file(self, data: Dict[str, Any]):
        """Persists connections dict to connections.json."""
        if active():
            write_document("connections", data)
            return
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return
        except Exception as e:
            logger.warning(f"Could not write connections to primary {self.file_path}: {e}")

        try:
            fallback = Path.home() / ".crisp" / "connections.json"
            if self.file_path != fallback:
                self.file_path = fallback
                self.file_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
        except Exception as fallback_err:
            logger.warning(f"Could not persist connections to disk ({fallback_err}); keeping in-memory only")

    def get_connection(self, category: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves connection data with decrypted password for INTERNAL backend use only.
        NEVER pass the return value directly into any API response!
        """
        cat = _normalize_category(category)
        data = self._read_file()
        conn = data.get(cat)
        if not conn:
            return None

        # Create copy and decrypt password
        conn_copy = dict(conn)
        enc_pwd = conn_copy.get("encrypted_password", "")
        conn_copy["password"] = decrypt_credential(enc_pwd) if enc_pwd else ""
        return conn_copy

    def get_public_connection(self, category: str) -> Optional[Dict[str, Any]]:
        """
        Returns sanitized connection details safe for API responses.
        Explicitly excludes any password or encrypted_password field.
        """
        cat = _normalize_category(category)
        data = self._read_file()
        conn = data.get(cat)
        if not conn:
            return None

        return {
            "category": cat,
            "connected": conn.get("connected", False),
            "base_url": conn.get("base_url", ""),
            "username": conn.get("username", ""),
            "last_tested": conn.get("last_tested"),
            "last_test_result": conn.get("last_test_result"),
            "last_test_detail": conn.get("last_test_detail", "")
        }

    def get_all_public(self) -> Dict[str, Any]:
        """
        Returns status of all connections without any password fields.
        Always returns structure for both 'siem' and 'iam' even if not yet configured.
        """
        data = self._read_file()
        result = {}
        for cat in ["siem", "iam"]:
            if cat in data:
                c = data[cat]
                result[cat] = {
                    "connected": c.get("connected", False),
                    "base_url": c.get("base_url", ""),
                    "username": c.get("username", ""),
                    "last_tested": c.get("last_tested"),
                    "last_test_result": c.get("last_test_result"),
                    "last_test_detail": c.get("last_test_detail", "")
                }
            else:
                result[cat] = {
                    "connected": False,
                    "base_url": "",
                    "username": "",
                    "last_tested": None,
                    "last_test_result": None,
                    "last_test_detail": "Not configured"
                }
        return result

    def test_connection(
        self,
        category: str,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Performs a real, live read-only test using the connector for the category.
        If parameters are omitted, falls back to saved credentials.
        Returns {"success": True/False, "detail": "human-readable message"}.
        """
        cat = _normalize_category(category)

        # Fall back to saved connection if credentials not passed
        if not base_url or password is None:
            saved = self.get_connection(cat)
            if not saved:
                return {
                    "success": False,
                    "detail": f"No credentials provided or saved for connection category '{category}'."
                }
            base_url = base_url or saved.get("base_url")
            username = username if username is not None else saved.get("username")
            password = password if password is not None else saved.get("password")

        if not base_url:
            return {"success": False, "detail": "Base URL cannot be empty."}

        base_url = base_url.strip().rstrip("/")

        if cat == "siem":
            try:
                connector = WazuhConnector(base_url=base_url, username=username or "", password=password or "")
                agent_res = connector.fetch_agent_status()
                total = agent_res.get("total_agents", 0)
                active = agent_res.get("active_agents", 0)
                cov = agent_res.get("agent_coverage_pct", 0.0)
                detail = f"Found {total} agents ({active} active, {cov}% coverage)"
                return {"success": True, "detail": detail}
            except Exception as e:
                return {"success": False, "detail": str(e)}

        elif cat == "iam":
            try:
                connector = KeycloakConnector(base_url=base_url, username=username or "", password=password or "")
                iam_res = connector.fetch_mfa_coverage()
                total = iam_res.get("total_privileged_accounts", 0)
                mfa_cnt = iam_res.get("mfa_enabled_count", 0)
                cov = iam_res.get("mfa_coverage_pct", 0.0)
                detail = f"Found {total} privileged accounts ({mfa_cnt} MFA active, {cov}% coverage)"
                return {"success": True, "detail": detail}
            except Exception as e:
                return {"success": False, "detail": str(e)}

        else:
            return {"success": False, "detail": f"Unknown connection category '{category}'. Must be 'siem' or 'iam'."}

    def save_connection(
        self,
        category: str,
        base_url: str,
        username: str,
        password: str,
        test_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Encrypts password and saves connection.
        If password is empty and connection already exists, preserves previously encrypted password.
        Runs live test if test_result not provided.
        Returns sanitized public connection information.
        """
        cat = _normalize_category(category)
        if cat not in ["siem", "iam"]:
            raise ValueError(f"Invalid connection category '{category}'. Must be 'siem' or 'iam'.")

        data = self._read_file()
        existing = data.get(cat, {})

        if not password and existing.get("encrypted_password"):
            enc_pwd = existing["encrypted_password"]
            dec_pwd = decrypt_credential(enc_pwd)
        else:
            enc_pwd = encrypt_credential(password or "")
            dec_pwd = password or ""

        # Run test if not provided
        if test_result is None:
            test_result = self.test_connection(cat, base_url=base_url, username=username, password=dec_pwd)

        now = datetime.now(timezone.utc).isoformat()
        is_success = bool(test_result.get("success"))

        data[cat] = {
            "connected": is_success,
            "base_url": base_url.strip(),
            "username": username.strip() if username else "",
            "encrypted_password": enc_pwd,
            "last_tested": now,
            "last_test_result": "SUCCESS" if is_success else "FAILED",
            "last_test_detail": test_result.get("detail", "")
        }

        self._write_file(data)

        return self.get_public_connection(cat)

    def record_connection_result(self, category: str, success: bool, detail: str):
        """Update a saved connection check without changing its encrypted credentials."""
        cat = _normalize_category(category)
        data = self._read_file()
        if cat not in data:
            return None
        data[cat].update(connected=success, last_tested=datetime.now(timezone.utc).isoformat(),
                         last_test_result="SUCCESS" if success else "FAILED", last_test_detail=detail)
        self._write_file(data)
        return self.get_public_connection(cat)

    def remove_connection(self, category: str) -> bool:
        """Removes a saved connection."""
        cat = _normalize_category(category)
        data = self._read_file()
        if cat in data:
            del data[cat]
            self._write_file(data)
            return True
        return False


# Singleton instance for application use
connections_store = ConnectionsStore()
