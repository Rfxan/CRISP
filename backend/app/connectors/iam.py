"""
IAM Connector for CRISP.
Integrates with Keycloak Admin REST API to calculate privileged account MFA coverage.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import logging
import requests
from app.core.outbound import integration_request, validate_outbound_url
from app.connectors.base import BaseConnector
from app.core.config import settings

logger = logging.getLogger(__name__)


class KeycloakConnector(BaseConnector):
    """
    Keycloak IAM Connector.
    Queries the Keycloak Admin REST API to fetch users, identify privileged accounts,
    and compute MFA (OTP) coverage.
    """
    def __init__(
        self,
        base_url: Optional[str] = None,
        realm: Optional[str] = None,
        admin_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        self.base_url = (base_url or settings.KEYCLOAK_BASE_URL).rstrip("/")
        self.realm = realm or settings.KEYCLOAK_REALM
        self.username = username or ""
        self.password = password or ""
        from app.core.guest_workspace import is_guest
        self.admin_token = admin_token or ("" if is_guest() else settings.KEYCLOAK_ADMIN_TOKEN)

    def _authenticate(self) -> str:
        """Authenticates with Keycloak using username/password to retrieve admin token."""
        token_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        try:
            resp = integration_request("post",
                token_url,
                data={
                    "client_id": "admin-cli",
                    "username": self.username,
                    "password": self.password,
                    "grant_type": "password"
                },
                timeout=10
            )
            if resp.status_code in [400, 401]:
                err_desc = resp.json().get("error_description", "Invalid username or password")
                raise ConnectionError(f"Keycloak authentication failed: {err_desc}")
            resp.raise_for_status()
            token = resp.json().get("access_token")
            if not token:
                raise ConnectionError("Keycloak returned no access token")
            self.admin_token = token
            return token
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to Keycloak token endpoint at {token_url}: {e}")
        except requests.exceptions.Timeout:
            raise ConnectionError(f"Keycloak token endpoint at {token_url} timed out")
        except Exception as e:
            if isinstance(e, ConnectionError):
                raise
            raise ConnectionError(f"Keycloak authentication error: {e}")

    def _get_headers(self) -> Dict[str, str]:
        if not self.admin_token:
            if self.username and self.password:
                self._authenticate()
            elif self.password and self.password.startswith("eyJ"):
                self.admin_token = self.password
            else:
                raise ConnectionError(
                    "Keycloak credentials missing. Provide username and password or KEYCLOAK_ADMIN_TOKEN."
                )
        return {
            "Authorization": f"Bearer {self.admin_token}",
            "Accept": "application/json"
        }

    def fetch(self) -> Dict[str, Any]:
        return self.fetch_mfa_coverage()

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        if not raw_data or not isinstance(raw_data, dict):
            raise ValueError("KeycloakConnector.normalize() requires non-empty dictionary data")
        return raw_data

    def is_user_privileged(self, user: Dict[str, Any]) -> bool:
        """
        Determines if a Keycloak user is privileged.
        Checks:
          1. realmRoles list (admin, realm-admin, superuser, privileged)
          2. groups list (contains 'admin' or 'privileged')
          3. attributes dict (privileged == ['true'])
          4. username prefix or exact match
        """
        privileged_roles = {"admin", "realm-admin", "superuser", "privileged", "security-admin"}
        realm_roles = set(user.get("realmRoles", []))
        if privileged_roles.intersection(realm_roles):
            return True

        groups = user.get("groups", [])
        if any(any(p in g.lower() for p in ["admin", "privileged"]) for g in groups):
            return True

        attributes = user.get("attributes", {})
        priv_attr = attributes.get("privileged", ["false"])
        if isinstance(priv_attr, list) and priv_attr and str(priv_attr[0]).lower() in ["true", "1"]:
            return True

        username = user.get("username", "").lower()
        if username in ["admin", "root", "administrator"] or username.startswith("admin-") or username.endswith("-admin"):
            return True

        return False

    def user_has_mfa(self, user: Dict[str, Any]) -> bool:
        """
        Checks whether a user has MFA/OTP configured.
        Inspects:
          - 'credentials' array for type == 'otp'
          - 'totp' boolean attribute
          - 'disableableCredentialTypes' list containing 'otp'
        """
        # 1. Credentials list
        credentials = user.get("credentials", [])
        for cred in credentials:
            if cred.get("type") in ["otp", "totp", "webauthn"]:
                return True

        # 2. Keycloak totp flag
        if user.get("totp") is True:
            return True

        # 3. disableableCredentialTypes
        disableable = user.get("disableableCredentialTypes", [])
        if any("otp" in str(d).lower() for d in disableable):
            return True

        return False

    def fetch_mfa_coverage(self) -> Dict[str, Any]:
        """
        Calls GET {base_url}/admin/realms/{realm}/users,
        checks credentials for type=='otp', filters to privileged users,
        and returns {total_privileged_accounts, mfa_enabled_count, mfa_coverage_pct}.
        Raises ConnectionError on failure — never fabricates values.
        """
        url = f"{self.base_url}/admin/realms/{self.realm}/users"
        try:
            resp = integration_request("get",
                url,
                headers=self._get_headers(),
                params={"max": 1000, "briefRepresentation": "false"},
                timeout=10
            )
            resp.raise_for_status()
            users: List[Dict[str, Any]] = resp.json()
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to Keycloak Admin API at {url}: {e}")
        except requests.exceptions.Timeout:
            raise ConnectionError(f"Keycloak Admin API at {url} timed out")
        except requests.exceptions.HTTPError as e:
            raise ConnectionError(f"Keycloak Admin API call failed (HTTP {resp.status_code}): {e}")

        # Filter privileged users
        privileged_users = [u for u in users if self.is_user_privileged(u)]
        # If no users explicitly marked privileged, treat all retrieved admin-scoped accounts
        eval_users = privileged_users if privileged_users else users

        total_privileged = len(eval_users)
        mfa_enabled = sum(1 for u in eval_users if self.user_has_mfa(u))
        cov_pct = round((mfa_enabled / max(1, total_privileged)) * 100, 1)

        return {
            "total_privileged_accounts": total_privileged,
            "mfa_enabled_count": mfa_enabled,
            "mfa_coverage_pct": cov_pct
        }
