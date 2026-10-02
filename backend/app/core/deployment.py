"""Deployment settings for the single-workspace application."""
import os
from cryptography.fernet import Fernet


def requires_hosted_database():
    return (os.getenv("RENDER") == "true" or
            (os.getenv("VERCEL") == "1" and os.getenv("VERCEL_ENV") != "development"))


def production():
    return os.getenv("CRISP_ENV", "development").lower() == "production" or requires_hosted_database()


def validate_deployment():
    if requires_hosted_database():
        url = os.getenv("CRISP_DATABASE_URL", "").strip()
        if not url.startswith(("postgresql://", "postgres://")):
            raise RuntimeError("Hosted deployments require a hosted PostgreSQL CRISP_DATABASE_URL")
    if production():
        try:
            Fernet(os.getenv("CRISP_ENCRYPTION_KEY", "").encode())
        except Exception as exc:
            raise RuntimeError("Production requires a valid persistent CRISP_ENCRYPTION_KEY") from exc
