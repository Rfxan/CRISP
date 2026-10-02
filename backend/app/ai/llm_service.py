"""
CRISP Multi-Provider LLM Service.
Connects to Google Gemini, OpenAI, Groq, Anthropic Claude, Local Ollama, and OpenAI-compatible endpoints.
Provides executive-level narrative generation grounded in deterministic FAIR metrics.
"""

import time
import logging
from typing import Dict, Any, Optional
import httpx
from app.core.outbound import validate_outbound_url
from openai import OpenAI

from app.ai.llm_config_store import llm_config_store, DEFAULT_MODELS, DEFAULT_BASE_URLS

logger = logging.getLogger(__name__)


class LLMService:
    @staticmethod
    def _get_client_for_provider(provider: str, api_key: str, base_url: str = None, timeout: float = 25.0, max_retries: int = 2) -> OpenAI:
        """Instantiates an OpenAI SDK client configured for the specific provider."""
        provider = provider.lower()
        active_url = (base_url or "").strip() or DEFAULT_BASE_URLS.get(provider) or None

        if provider == "gemini":
            active_url = active_url or "https://generativelanguage.googleapis.com/v1beta/openai/"
        elif provider == "groq":
            active_url = active_url or "https://api.groq.com/openai/v1"
        elif provider == "deepseek":
            active_url = active_url or "https://api.deepseek.com"
        elif provider == "ollama":
            active_url = active_url or "http://localhost:11434/v1"
            api_key = api_key or "ollama"

        return OpenAI(
            api_key=api_key or "dummy_key",
            base_url=active_url,
            timeout=timeout,
            max_retries=max_retries,
            http_client=httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False,
                event_hooks={"request": [lambda request: validate_outbound_url(str(request.url), provider=True)]})
        )

    @staticmethod
    def generate_response(
        prompt: str,
        system_context: str,
        config: Optional[Dict[str, Any]] = None,
        timeout: float = 25.0,
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """
        Executes a completion against the configured LLM provider.
        """
        cfg = config or llm_config_store.get_config()
        provider = (cfg.get("provider") or "gemini").lower()
        model = cfg.get("model") or DEFAULT_MODELS.get(provider, "gemini-1.5-flash")
        api_key = (cfg.get("api_key") or "").strip()
        base_url = (cfg.get("base_url") or "").strip()
        temperature = float(cfg.get("temperature", 0.2))

        if not api_key and provider != "ollama":
            raise ValueError(f"No API key configured for {provider.capitalize()}. Please set your API key in AI Settings.")

        start_time = time.time()

        # Provider 1: Anthropic Claude (Direct Messages API)
        if provider == "anthropic":
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            body = {
                "model": model,
                "max_tokens": 1200,
                "system": system_context,
                "messages": [{"role": "user", "content": prompt}]
            }
            # Only add temperature if not using models that deprecate it
            if not any(k in model for k in ["-5", "-4-6", "-4-7", "-4-8"]):
                body["temperature"] = temperature

            with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False,
                    event_hooks={"request": [lambda request: validate_outbound_url(str(request.url), provider=True)]}) as client:
                res = client.post("https://api.anthropic.com/v1/messages", headers=headers, json=body)
                if not res.is_success and res.status_code == 400 and "temperature" in res.text:
                    # Retry without temperature for models that deprecate temperature
                    body.pop("temperature", None)
                    res = client.post("https://api.anthropic.com/v1/messages", headers=headers, json=body)

                if not res.is_success:
                    err_msg = res.json().get("error", {}).get("message", res.text)
                    raise RuntimeError(f"Anthropic API Error ({res.status_code}): {err_msg}")
                data = res.json()
                answer = data.get("content", [{}])[0].get("text", "")

        # Provider 2: Gemini Direct fallback (if needed) or via OpenAI compatibility
        elif provider == "gemini":
            try:
                client = LLMService._get_client_for_provider("gemini", api_key, base_url, timeout=timeout, max_retries=max_retries)
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_context},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=temperature,
                    max_tokens=1200
                )
                answer = response.choices[0].message.content or ""
            except Exception as direct_err:
                logger.info("OpenAI-compat Gemini failed, trying native REST")
                rest_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
                rest_body = {
                    "systemInstruction": {"parts": [{"text": system_context}]},
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": temperature, "maxOutputTokens": 1200}
                }
                with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False,
                        event_hooks={"request": [lambda request: validate_outbound_url(str(request.url), provider=True)]}) as http_c:
                    r = http_c.post(rest_url, json=rest_body, headers={"x-goog-api-key": api_key})
                    if not r.is_success:
                        raise RuntimeError(f"Gemini API Error ({r.status_code}): {r.text}")
                    gem_data = r.json()
                    candidates = gem_data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        parts = candidates[0]["content"].get("parts", [])
                        answer = "".join(p.get("text", "") for p in parts)
                    else:
                        raise RuntimeError(f"Unexpected Gemini response structure: {gem_data}")

        # Provider 3: OpenAI, DeepSeek, Groq, Ollama, Custom (All standard OpenAI-compatible)
        else:
            client = LLMService._get_client_for_provider(provider, api_key, base_url, timeout=timeout, max_retries=max_retries)
            
            # Special handling for reasoning models (OpenAI o1/o3 or DeepSeek-reasoner)
            is_o_series = provider == "openai" and (model.startswith("o1") or model.startswith("o3"))
            is_reasoner = is_o_series or model == "deepseek-reasoner"

            messages = [
                {"role": "system" if not is_o_series else "user", "content": system_context},
                {"role": "user", "content": prompt}
            ]

            kwargs = {
                "model": model,
                "messages": messages
            }

            if is_o_series:
                kwargs["max_completion_tokens"] = 1200
            elif is_reasoner:
                kwargs["max_tokens"] = 1200
            else:
                kwargs["temperature"] = temperature
                kwargs["max_tokens"] = 1200

            response = client.chat.completions.create(**kwargs)
            answer = response.choices[0].message.content or ""

        duration_ms = int((time.time() - start_time) * 1000)

        return {
            "answer": answer.strip(),
            "provider": provider,
            "model": model,
            "latency_ms": duration_ms
        }

    @staticmethod
    def test_connection(config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates LLM credentials by sending a lightweight test probe with short timeout.
        """
        provider = (config.get("provider") or "gemini").lower()
        model = config.get("model") or DEFAULT_MODELS.get(provider, "gemini-1.5-flash")
        api_key = (config.get("api_key") or "").strip()
        base_url = (config.get("base_url") or "").strip()

        # If user passed masked key, fetch real key from stored config
        if not api_key or "••••" in api_key:
            stored = llm_config_store.get_config()
            if stored.get("provider") == provider:
                api_key = (stored.get("api_key") or "").strip()

        if not api_key and provider != "ollama":
            return {
                "connected": False,
                "provider": provider,
                "model": model,
                "error": f"API key is required for {provider.capitalize()}."
            }

        start = time.time()
        try:
            test_prompt = "Hello! Please reply with exactly one word: 'CONNECTED'."
            test_system = "You are a test probe. Answer with only 'CONNECTED'."

            test_cfg = {
                "provider": provider,
                "model": model,
                "api_key": api_key,
                "base_url": base_url,
                "temperature": 0.0
            }
            # Fast 3.0 second probe with 0 retries
            res = LLMService.generate_response(test_prompt, test_system, test_cfg, timeout=3.0, max_retries=0)
            latency = int((time.time() - start) * 1000)

            return {
                "connected": True,
                "provider": provider,
                "model": model,
                "latency_ms": latency,
                "detail": f"Successfully authenticated with {provider.capitalize()} ({model}). Probe latency: {latency}ms."
            }
        except Exception as e:
            latency = int((time.time() - start) * 1000)
            err_str = "Provider connection failed; check the server configuration and credentials"
            return {
                "connected": False,
                "provider": provider,
                "model": model,
                "latency_ms": latency,
                "error": err_str
            }


llm_service = LLMService()
