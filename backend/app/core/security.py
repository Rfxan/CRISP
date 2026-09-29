"""
CRISP Security & Credential Encryption Module.

Provides symmetric credential encryption/decryption using Fernet.
The encryption key MUST be supplied via the CRISP_ENCRYPTION_KEY environment variable.

SETUP INSTRUCTIONS:
To generate an encryption key once, run:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
Then add the generated key to your .env file:
    CRISP_ENCRYPTION_KEY=<generated_key>

Never hardcode the key in source code.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# Automatically load .env if present in backend or root directory
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()


import logging

logger = logging.getLogger(__name__)

_ephemeral_fernet = None


def _get_fernet() -> Fernet:
    """
    Retrieves Fernet cipher instance using CRISP_ENCRYPTION_KEY env var.
    If CRISP_ENCRYPTION_KEY is absent, degrades gracefully to an in-memory
    ephemeral key with a warning so the application boots and runs with zero
    mandatory environment variables.
    """
    global _ephemeral_fernet
    key = os.getenv("CRISP_ENCRYPTION_KEY")
    if not key or not key.strip():
        if _ephemeral_fernet is None:
            logger.warning(
                "CRISP_ENCRYPTION_KEY environment variable is not set. "
                "Degrading gracefully to an in-memory ephemeral encryption key for this session. "
                "Encrypted credentials will not persist across service restarts."
            )
            _ephemeral_fernet = Fernet(Fernet.generate_key())
        return _ephemeral_fernet

    try:
        return Fernet(key.strip().encode("utf-8"))
    except Exception as e:
        if _ephemeral_fernet is None:
            logger.warning(
                f"Invalid CRISP_ENCRYPTION_KEY format ({e}). "
                "Degrading gracefully to an in-memory ephemeral key for this session."
            )
            _ephemeral_fernet = Fernet(Fernet.generate_key())
        return _ephemeral_fernet


def encrypt_credential(plaintext: str) -> str:
    """Encrypts plaintext string using Fernet symmetric encryption."""
    if plaintext is None:
        return ""
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    if not plaintext:
        return ""
    fernet = _get_fernet()
    return fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_credential(ciphertext: str) -> str:
    """Decrypts Fernet ciphertext string back to plaintext."""
    if not ciphertext:
        return ""
    fernet = _get_fernet()
    return fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
