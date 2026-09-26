import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

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

settings = Settings()
