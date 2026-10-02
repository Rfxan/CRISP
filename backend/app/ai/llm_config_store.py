from app.core.tenancy import active, read_document, write_document, principal_context
from app.core.deployment import production
"""
CRISP LLM Configuration Store.
Manages persistent configuration for multi-provider LLM integrations (Gemini, OpenAI, Groq, Anthropic, Ollama, Custom).
Encrypts API keys symmetrically using Fernet before saving to llm_config.json.
API keys are never exposed in plaintext over public API endpoints.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from app.core.config import DATA_DIR
from app.core.security import encrypt_credential, decrypt_credential
from app.core.outbound import validate_outbound_url

logger = logging.getLogger(__name__)

DEFAULT_MODELS = {
    "gemini": "gemini-2.0-flash",
    "openai": "gpt-4o-mini",
    "groq": "llama-3.3-70b-versatile",
    "anthropic": "claude-sonnet-5",
    "deepseek": "deepseek-chat",
    "ollama": "deepseek-r1",
    "custom": "custom-model"
}

DEFAULT_BASE_URLS = {
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/",
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "deepseek": "https://api.deepseek.com",
    "ollama": "http://localhost:11434/v1",
    "custom": ""
}


def _get_storage_path() -> Path:
    """Returns primary path in DATA_DIR or fallback outside protected Documents folder."""
    primary = DATA_DIR / "llm_config.json"
    if production():
        return primary  # No startup writes into the read-only function bundle.
    
    # Check if primary directory is writable
    try:
        primary.parent.mkdir(parents=True, exist_ok=True)
        # Test writeability
        test_file = primary.parent / ".perm_check"
        test_file.write_text("ok")
        test_file.unlink(missing_ok=True)
        return primary
    except (OSError, PermissionError):
        try:
            fallback = Path.home() / ".crisp" / "llm_config.json"
            fallback.parent.mkdir(parents=True, exist_ok=True)
            return fallback
        except Exception:
            return primary


class LLMConfigStore:
    def __init__(self, storage_file: Optional[Path] = None):
        self.file_path = storage_file or _get_storage_path()
        self._ensure_file()

    def _ensure_file(self):
        """Ensures the llm_config.json file exists and is valid JSON."""
        if active() or production():
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
        self._ensure_file()
        if active():
            document = read_document("llm_config")
            if document is None and not production() and principal_context.get()["tenant"] == "local":
                try:
                    document = json.loads(self.file_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    document = {}
                write_document("llm_config", document)
            return document or {}
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not read {self.file_path}: {e}")
            return {}

    def _write_file(self, data: Dict[str, Any]):
        if active():
            write_document("llm_config", data)
            return
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return
        except Exception as e:
            logger.warning(f"Could not write to primary {self.file_path}: {e}")

        # Fallback to home dir or temp dir if primary fails
        try:
            fallback = Path.home() / ".crisp" / "llm_config.json"
            if self.file_path != fallback:
                self.file_path = fallback
                self.file_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
        except Exception as fallback_err:
            logger.warning(f"Could not persist config to disk ({fallback_err}); keeping in-memory only")

    def get_config(self) -> Dict[str, Any]:
        """
        Retrieves active configuration, falling back to environment variables if not saved in json.
        Returns decrypted API key for internal server use.
        """
        stored = self._read_file()

        provider = (stored.get("provider") or os.getenv("LLM_PROVIDER", "gemini")).lower()
        model = stored.get("model") or os.getenv("LLM_MODEL") or DEFAULT_MODELS.get(provider, "gemini-1.5-flash")
        base_url = stored.get("base_url") or os.getenv("LLM_BASE_URL") or DEFAULT_BASE_URLS.get(provider, "")
        temperature = float(stored.get("temperature", 0.2))
        enabled = stored.get("enabled", True)

        # Retrieve API key: first check encrypted stored key, then check env vars
        api_key = ""
        enc_key = stored.get("encrypted_api_key")
        if enc_key:
            try:
                api_key = decrypt_credential(enc_key)
            except Exception as e:
                logger.error(f"Failed to decrypt stored LLM API key: {e}")

        if not api_key and (not active() or (not production() and principal_context.get()["tenant"] == "local")):
            if provider == "openai":
                api_key = os.getenv("OPENAI_API_KEY", "")
            elif provider == "gemini":
                api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY", "")
            elif provider == "groq":
                api_key = os.getenv("GROQ_API_KEY", "")
            elif provider == "anthropic":
                api_key = os.getenv("ANTHROPIC_API_KEY", "")
            elif provider == "deepseek":
                api_key = os.getenv("DEEPSEEK_API_KEY", "")
            elif provider == "ollama":
                api_key = "ollama"

        return {
            "provider": provider,
            "model": model,
            "base_url": base_url,
            "api_key": api_key,
            "temperature": temperature,
            "enabled": enabled
        }

    def get_public_config(self) -> Dict[str, Any]:
        """
        Returns safe public view of LLM config for frontend consumption.
        Masks the API key so secret credentials are never leaked.
        """
        cfg = self.get_config()
        raw_key = cfg.get("api_key", "")

        masked_key = ""
        if raw_key:
            if len(raw_key) > 8:
                masked_key = raw_key[:4] + "••••••••" + raw_key[-4:]
            else:
                masked_key = "••••••••"

        return {
            "provider": cfg["provider"],
            "model": cfg["model"],
            "base_url": cfg["base_url"],
            "has_api_key": bool(raw_key),
            "masked_api_key": masked_key,
            "temperature": cfg["temperature"],
            "enabled": cfg["enabled"],
            "available_providers": [
                {"id": "gemini", "name": "Google Gemini", "default_model": "gemini-2.0-flash"},
                {"id": "anthropic", "name": "Anthropic Claude", "default_model": "claude-3-7-sonnet-20250219"},
                {"id": "openai", "name": "OpenAI", "default_model": "gpt-4o-mini"},
                {"id": "deepseek", "name": "DeepSeek", "default_model": "deepseek-chat"},
                {"id": "groq", "name": "Groq (Fast Open-Source)", "default_model": "llama-3.3-70b-versatile"},
                {"id": "ollama", "name": "Local Ollama", "default_model": "deepseek-r1"},
                {"id": "custom", "name": "Custom OpenAI-Compatible", "default_model": "custom-model"}
            ]
        }

    def save_config(self, provider: str, model: str = None, api_key: str = None, base_url: str = None, temperature: float = 0.2, enabled: bool = True) -> Dict[str, Any]:
        """
        Saves updated LLM configuration with symmetrically encrypted API key.
        """
        provider = (provider or "gemini").lower()
        model = model or DEFAULT_MODELS.get(provider, "gemini-1.5-flash")
        base_url = base_url if base_url is not None else DEFAULT_BASE_URLS.get(provider, "")
        if base_url:
            validate_outbound_url(base_url, provider=True)

        current = self._read_file()
        update_data = {
            "provider": provider,
            "model": model,
            "base_url": base_url,
            "temperature": float(temperature),
            "enabled": bool(enabled)
        }

        # If a new API key was entered (not the masked version)
        if api_key and not api_key.startswith("••") and "••••" not in api_key:
            update_data["encrypted_api_key"] = encrypt_credential(api_key.strip())
        elif "encrypted_api_key" in current and (not api_key or "••••" in api_key):
            # Preserve existing encrypted key if user didn't modify it
            update_data["encrypted_api_key"] = current["encrypted_api_key"]

        self._write_file(update_data)
        return self.get_public_config()


llm_config_store = LLMConfigStore()
