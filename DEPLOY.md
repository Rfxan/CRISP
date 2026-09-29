# CRISP Deployment Guide: Render (Backend) & Vercel (Frontend)

This guide documents the deployment configuration, environment variables, build/start commands, and architectural setup for deploying CRISP to **Render** (FastAPI backend) and **Vercel** (React/Vite frontend).

---

## Architecture Overview

```
[ Browser / Client ]
         |
         | (HTTPS)
         v
[ Vercel Edge (Frontend) ]
   ├── Static Assets (React / Vite bundle)
   └── vercel.json rewrite: /api/:path* ──(Reverse Proxy)──> [ Render (Backend) ]
                                                               └── FastAPI (:PORT)
                                                                   ├── PuLP / CBC Solver
                                                                   ├── FAIR Engine
                                                                   ├── In-Memory / File Store
                                                                   └── LLM Integrations
```

- **Frontend (`frontend/`)**: Static SPA built with Vite and React. Calls the backend using relative URLs (`/api/...`).
- **Edge Routing (`frontend/vercel.json`)**: Transparently proxies `/api/*` requests to the Render backend, eliminating Cross-Origin Resource Sharing (CORS) complexity in production.
- **Backend (`backend/`)**: FastAPI application serving REST endpoints, calculating risk via FAIR Monte Carlo simulations, and optimizing remediation using PuLP/CBC linear programming.

---

## 1. Backend Deployment (Render)

### Service Configuration
- **Environment**: Python 3.11 or 3.12
- **Root Directory**: `backend` (or repo root with `--app-dir backend`)
- **Build Command**:
  ```bash
  pip install -r requirements.txt
  ```
- **Start Command**:
  ```bash
  uvicorn app.main:app --host 0.0.0.0 --port $PORT
  ```

> **Note on `$PORT`**: Render dynamically provides a `$PORT` environment variable. The start command binds uvicorn to `0.0.0.0` and `$PORT` (defaulting to 8000 when tested locally).

---

### Backend Environment Variables Reference

| Variable Name | Required? | Default | Description |
| :--- | :---: | :---: | :--- |
| **`PORT`** | Optional | `8000` | Port for the uvicorn HTTP server. Provided automatically by Render. |
| **`CRISP_ENCRYPTION_KEY`** | **Recommended** | *Ephemeral* | 32-url-safe-base64-encoded Fernet key used to encrypt saved credentials in the connection store (`connections_store.json`). If omitted, CRISP generates a secure in-memory ephemeral key at boot and logs a warning (persisted credentials will not survive restarts without a fixed key). |
| **`LLM_PROVIDER`** | Optional | `gemini` | Default LLM provider for AI risk narratives: `gemini`, `openai`, `anthropic`, `groq`, `deepseek`, or `ollama`. |
| **`LLM_MODEL`** | Optional | Provider default | Override model name (e.g. `gemini-1.5-flash`, `gpt-4o-mini`, `claude-3-5-sonnet-latest`). |
| **`LLM_BASE_URL`** | Optional | Provider default | Custom API base URL (useful for custom Ollama or local LLM proxies). |
| **`GEMINI_API_KEY`** / **`GOOGLE_API_KEY`** | Optional | `""` | API key for Google Gemini LLM provider. |
| **`OPENAI_API_KEY`** | Optional | `""` | API key for OpenAI LLM provider. |
| **`ANTHROPIC_API_KEY`** | Optional | `""` | API key for Anthropic Claude LLM provider. |
| **`GROQ_API_KEY`** | Optional | `""` | API key for Groq LLM provider. |
| **`DEEPSEEK_API_KEY`** | Optional | `""` | API key for DeepSeek LLM provider. |
| **`NVD_API_KEY`** | Optional | `""` | NIST NVD API v2 key. Increases rate limit from 5 requests/30s to 50 requests/30s for faster threat intelligence synchronization. |
| **`WAZUH_BASE_URL`** | Optional | `https://localhost:55000` | Wazuh Manager API endpoint for telemetry ingestion. |
| **`WAZUH_USERNAME`** | Optional | `wazuh-wui` | Wazuh API username. |
| **`WAZUH_PASSWORD`** | Optional | `wazuh-wui` | Wazuh API password. |
| **`KEYCLOAK_BASE_URL`** | Optional | `http://localhost:8080` | Keycloak Identity Provider endpoint. |
| **`KEYCLOAK_REALM`** | Optional | `master` | Keycloak realm name. |
| **`KEYCLOAK_ADMIN_TOKEN`** | Optional | `""` | Keycloak administrative service token. |

#### Generating a Production Encryption Key
To set `CRISP_ENCRYPTION_KEY` on Render, generate a valid key using:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Paste the output into the **Environment Variables** tab in your Render Web Service dashboard.

---

### Zero-Configuration Graceful Boot
The backend is engineered to boot successfully with **zero required environment variables**:
- If `CRISP_ENCRYPTION_KEY` is absent, an ephemeral key is generated in memory and a warning is logged.
- If LLM API keys are absent, AI narrative endpoints degrade gracefully, returning informational warnings rather than crashing.
- External integrations (Wazuh, Keycloak) remain inactive until configured in the UI or environment.

---

### PuLP / CBC Optimization Engine
The remediation optimizer uses the **PuLP** linear programming library with the **COIN-OR CBC** solver:
- On Linux (Render standard environment) and Windows, `pulp` packages the pre-compiled `cbc` binary (`PULP_CBC_CMD`).
- If CBC is ever missing in a custom container, install `coinor-cbc` via the system package manager:
  ```bash
  apt-get update && apt-get install -y coinor-cbc
  ```
- The optimizer verifies solver availability at runtime before solving, preventing silent fallback to fake "optimal" results.

---

## 2. Frontend Deployment (Vercel)

### Project Configuration
- **Framework Preset**: `Vite`
- **Root Directory**: `frontend`
- **Build Command**: `npm run build`
- **Output Directory**: `dist`
- **Install Command**: `npm install`

---

### Edge Rewrite Configuration (`vercel.json`)
The frontend contains `frontend/vercel.json` to proxy all `/api/*` traffic to the backend:

```json
{
  "rewrites": [
    {
      "source": "/api/:path*",
      "destination": "https://YOUR-CRISP-BACKEND.onrender.com/api/:path*"
    }
  ]
}
```

> **ACTION REQUIRED BEFORE / AFTER DEPLOYING:**
> Replace `YOUR-CRISP-BACKEND.onrender.com` in `frontend/vercel.json` with your actual Render service URL (e.g. `https://crisp-api.onrender.com/api/:path*`).

---

### Frontend Code Verification
- All API client calls in `frontend/src/services/api.js` use the relative path `API_BASE = '/api'`.
- No hardcoded `localhost:8000` URLs exist in frontend production source code.

---

## 3. Deployment Verification Checklist

### Local / Pre-deploy Verification
1. **Fresh Virtualenv Clean Install**:
   ```bash
   python -m venv .test_venv
   # Windows:
   .test_venv\Scripts\activate
   # Linux/macOS:
   source .test_venv/bin/activate

   pip install -r backend/requirements.txt
   python -c "import app.main; print('Import succeeded with zero errors!')"
   ```

2. **Run Pytest Suite**:
   ```bash
   python -m pytest backend/tests -v
   ```

3. **Verify Render Boot Command with Empty Environment**:
   ```bash
   uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000
   ```

4. **Verify Live PuLP / CBC Solver**:
   ```bash
   curl -X POST http://localhost:8000/api/optimize \
     -H "Content-Type: application/json" \
     -d '{"budget": 500000.0}'
   ```
   *Expected response: JSON with `"status": "Optimal"`, calculated risk reduction, and selected controls/patches.*
