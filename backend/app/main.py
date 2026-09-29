import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler

from app.api.routes import router as api_router, sync_wazuh_telemetry, sync_iam_telemetry, store
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
    # Startup: schedule telemetry sync every 30 seconds
    scheduler.add_job(
        sync_telemetry_cycle,
        "interval",
        seconds=30,
        id="live_telemetry_sync",
        replace_existing=True
    )
    # Startup: schedule daily threat intel sync (KEV, EPSS, NVD)
    scheduler.add_job(
        sync_threat_intel_cycle,
        "interval",
        hours=24,
        id="daily_threat_intel_sync",
        replace_existing=True
    )
    scheduler.start()
    logger.info("CRISP Background Schedulers started (Telemetry: 30s, Threat Intel: 24h).")
    yield
    # Shutdown
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("CRISP Background Telemetry Scheduler stopped.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-Powered Continuous Cyber Risk Quantification & Investment Optimization Platform (SIH 26105)",
    lifespan=lifespan
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
