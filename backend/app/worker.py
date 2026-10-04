"""Run with python -m app.worker. API processes never start schedulers."""
import signal
import threading
import time
from app.core.deployment import validate_deployment
from app.core.tenancy import tenant_ids, tenant_transaction, read_document, write_document, audit
from app.core.state_proxy import bound_store, import_state, export_state


def sync_once(tenant, interval=30):
    from types import SimpleNamespace
    from app.core.sync_jobs import enqueue, run_job, TERMINAL
    identity = {"tenant": tenant, "subject": "sync-worker", "role": "admin"}
    request = SimpleNamespace(state=SimpleNamespace())
    now = time.time()
    with tenant_transaction(identity):
        last = read_document("sync_schedule", {})
        current = read_document("sync_job", {})
        if now-last.get("last_completed", 0) < interval:
            return False
        if current.get("status") not in TERMINAL and now-current.get("updated_at", 0) < 300:
            return False
        kind = "all" if now-last.get("last_intel", 0) >= 86400 else "telemetry"
        job = enqueue(request, kind)
    # The durable claim is committed before network retrieval begins.
    run_job(identity, job["id"])
    with tenant_transaction(identity):
        outcome = read_document("sync_job", {})
        last["last_completed"] = time.time()
        if kind == "all" and outcome.get("status") == "COMPLETED":
            last["last_intel"] = now
        last["failed_jobs"] = [name for name, status in outcome.get("job_results", {}).items()
                               if str(status).startswith("error") or status in ("FAILED", "DEGRADED")]
        write_document("sync_schedule", last)
    return True


def main():
    validate_deployment()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    while not stopped.is_set():
        for tenant in tenant_ids():
            try:
                sync_once(tenant)
            except Exception:
                import logging
                logging.exception("Synchronization failed for tenant")
        stopped.wait(5)


if __name__ == "__main__":
    main()
