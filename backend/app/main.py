import logging
from contextlib import asynccontextmanager
import os
from fastapi.responses import JSONResponse
from app.core.deployment import validate_deployment, production
from app.core.middleware import TenantMiddleware
from app.core.web_security import WebSecurityMiddleware, public_demo, read_only_demo, guest_mode
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler

from app.api.routes import router as api_router, sync_wazuh_telemetry, sync_wazuh_indexer, sync_iam_telemetry, store, get_active_snapshot
from app.core.config import settings
from app.core.connections_store import connections_store

logger = logging.getLogger(__name__)

# Continuous background telemetry synchronization job
scheduler = BackgroundScheduler(daemon=True)


def sync_telemetry_cycle():
    """
    Periodic background job to sync telemetry from configured SIEM & IAM connections.
    Records timestamp, source, counts, and status to sync_state.json.
    Diffs against snapshot state and only triggers engine recomputation if data changed.
    """
    # 1. Check & Sync SIEM (Wazuh)
    try:
        siem_conn = connections_store.get_connection("siem")
        if siem_conn and siem_conn.get("connected") and siem_conn.get("base_url"):
            logger.info(f"Telemetry Scheduler: Syncing live SIEM from {siem_conn['base_url']}...")
            sync_wazuh_telemetry(simulate=False)
        else:
            sync_wazuh_telemetry(simulate=False)
    except Exception as e:
        logger.warning(f"Telemetry Scheduler: SIEM sync error: {e}")

    try:
        sync_wazuh_indexer()
    except Exception:
        logger.warning("Telemetry Scheduler: Indexer sync failed")

    # 2. Check & Sync IAM (Keycloak)
    try:
        iam_conn = connections_store.get_connection("iam")
        if iam_conn and iam_conn.get("connected") and iam_conn.get("base_url"):
            logger.info(f"Telemetry Scheduler: Syncing live IAM from {iam_conn['base_url']}...")
            sync_iam_telemetry(simulate=False)
        else:
            sync_iam_telemetry(simulate=False)
    except Exception as e:
        logger.warning(f"Telemetry Scheduler: IAM sync error: {e}")


def sync_threat_intel_cycle():
    """
    Periodic background job to refresh live threat intelligence feeds:
    - CISA Known Exploited Vulnerabilities (KEV) catalog
    - FIRST EPSS scores
    - NIST NVD API v2 details
    Runs daily (interval: 24h) and degrades gracefully if offline.
    """
    try:
        logger.info("Threat Intel Scheduler: Syncing live CISA KEV, FIRST EPSS, and NIST NVD feeds...")
        store.sync_live_threat_intel()
    except Exception as e:
        logger.warning(f"Threat Intel Scheduler sync warning: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_deployment()
    yield



app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-Powered Continuous Cyber Risk Quantification & Investment Optimization Platform (SIH 26105)",
    docs_url=None if production() else "/docs",
    redoc_url=None if production() else "/redoc",
    openapi_url=None if production() else "/openapi.json",
    lifespan=lifespan
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CRISP_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)

app.add_middleware(TenantMiddleware)
app.add_middleware(WebSecurityMiddleware)


@app.exception_handler(ValueError)
async def invalid_input(request, exc):
    from app.core.errors import DomainValidationError
    return JSONResponse(status_code=422, content={"detail": str(exc) if isinstance(exc, DomainValidationError) or not production() else "Invalid input"})


@app.exception_handler(RequestValidationError)
async def invalid_request(request, exc):
    # Pydantic errors include submitted values, potentially passwords/API keys.
    errors = [{k: e[k] for k in ("loc", "msg", "type") if k in e} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(HTTPException)
async def http_error(request, exc):
    detail = "External service unavailable" if exc.status_code >= 500 else exc.detail
    return JSONResponse(status_code=exc.status_code, content={"detail": detail}, headers=exc.headers)


# Mount API routes
app.include_router(api_router, prefix="/api")


@app.get("/api/security/capabilities")
def security_capabilities():
    return {"public_demo": public_demo(), "can_edit": not read_only_demo(),
            "can_use_ai": not read_only_demo(), "guest_workspace": guest_mode()}


@app.get("/")
def root():
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "ONLINE",
        "api_docs": "/docs",
        "currency": "INR (\u20b9)",
        "tagline": "Not a risk score. A budget decision, with the proof."
    }


@app.get("/health")
@app.get("/api/health")
def health_check():
    return {"status": "ok", "platform": settings.PROJECT_NAME, "version": settings.VERSION}


@app.get("/snapshot")
def get_snapshot_root():
    """Returns active snapshot with deduplicated control states."""
    return get_active_snapshot()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
