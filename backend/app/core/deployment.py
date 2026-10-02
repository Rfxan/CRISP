"""Deployment settings for the single-workspace application."""
import os
from cryptography.fernet import Fernet


def production():
    return os.getenv("CRISP_ENV", "development").lower() == "production"


def validate_deployment():
    if production():
        try:
            Fernet(os.getenv("CRISP_ENCRYPTION_KEY", "").encode())
        except Exception as exc:
            raise RuntimeError("Production requires a valid persistent CRISP_ENCRYPTION_KEY") from exc
