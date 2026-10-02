import logging
from contextlib import asynccontextmanager
import os
from fastapi.responses import JSONResponse
from app.core.deployment import validate_deployment, production
from app.core.middleware import TenantMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler

from app.api.routes import router as api_router, sync_wazuh_telemetry, sync_iam_telemetry, store, get_active_snapshot
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
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(TenantMiddleware)


@app.exception_handler(ValueError)
async def invalid_input(request, exc):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


# Mount API routes
app.include_router(api_router, prefix="/api")


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
def health_check():
    return {"status": "ok", "platform": settings.PROJECT_NAME, "version": settings.VERSION}


@app.get("/snapshot")
def get_snapshot_root():
    """Returns active snapshot with deduplicated control states."""
    return get_active_snapshot()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
