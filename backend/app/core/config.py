import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

# Load .env from CRISP root directory
_env_path = BASE_DIR.parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path, override=False)
else:
    load_dotenv(override=False)

class Settings:
    PROJECT_NAME: str = "CRISP - Continuous Risk & Investment Simulation Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    DEFAULT_SEED: int = 42
    DEFAULT_TRIALS: int = 10000
    ASSUMPTIONS_VERSION: int = 4
    
    # Financial Calibration for Indian Context (in INR ₹)
    CURRENCY_SYMBOL: str = "₹"
    DEFAULT_RISK_APPETITE: float = 120_000_000.0  # ₹12 Crore
    DPDP_PENALTY_CEILING: float = 2_500_000_000.0 # ₹250 Crore max statutory ceiling
    DPDP_BREACH_NOTICE_CEILING: float = 2_000_000_000.0 # ₹200 Crore
    COST_PER_RECORD_INR: float = 2850.0 # Based on Indian BFSI breach reports

    # Wazuh SIEM / EDR settings
    WAZUH_BASE_URL: str = os.getenv("WAZUH_BASE_URL", "https://localhost:55000")
    WAZUH_USERNAME: str = os.getenv("WAZUH_USERNAME", "wazuh-wui")
    WAZUH_PASSWORD: str = os.getenv("WAZUH_PASSWORD", "wazuh-wui")

    # Keycloak IAM settings
    KEYCLOAK_BASE_URL: str = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8080")
    KEYCLOAK_REALM: str = os.getenv("KEYCLOAK_REALM", "master")
    KEYCLOAK_ADMIN_TOKEN: str = os.getenv("KEYCLOAK_ADMIN_TOKEN", "")

settings = Settings()
