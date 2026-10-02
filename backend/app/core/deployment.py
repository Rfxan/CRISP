"""Deployment settings for the single-workspace application."""
import os
from cryptography.fernet import Fernet


def production():
    return (os.getenv("CRISP_ENV", "development").lower() == "production" or
            (os.getenv("VERCEL") == "1" and os.getenv("VERCEL_ENV") != "development"))


def validate_deployment():
    if os.getenv("VERCEL") == "1" and os.getenv("VERCEL_ENV") != "development":
        url = os.getenv("CRISP_DATABASE_URL", "").strip()
        if not url.startswith(("postgresql://", "postgres://")):
            raise RuntimeError("Vercel deployments require a hosted PostgreSQL CRISP_DATABASE_URL")
    if production():
        try:
            Fernet(os.getenv("CRISP_ENCRYPTION_KEY", "").encode())
        except Exception as exc:
            raise RuntimeError("Production requires a valid persistent CRISP_ENCRYPTION_KEY") from exc
