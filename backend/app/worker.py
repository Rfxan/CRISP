"""Run with python -m app.worker. API processes never start schedulers."""
import signal
import threading
import time
from app.core.deployment import validate_deployment
from app.core.tenancy import tenant_ids, tenant_transaction, read_document, write_document, audit
from app.core.state_proxy import bound_store, import_state, export_state


def sync_once(tenant, interval=30):
    from app.api.routes import SnapshotStore, sync_wazuh_telemetry, sync_iam_telemetry
    # The due check and external sync stay in one transaction: another worker cannot
    # claim the same job, including after a lease timeout during a slow connector call.
    with tenant_transaction({"tenant":tenant,"subject":"sync-worker","role":"admin"}):
        now = time.time()
        last = read_document("sync_schedule", {})
        if now-last.get("last_completed",0) < interval:
            return False
        local = SnapshotStore()
        import_state(local, read_document("snapshot"))
        token = bound_store.set(local)
        try:
            failures = []
            for sync in (sync_wazuh_telemetry, sync_iam_telemetry):
                try:
                    sync(simulate=False)
                except Exception:
                    failures.append(sync.__name__)
            if now-last.get("last_intel",0) >= 86400:
                try:
                    local.sync_live_threat_intel()
                    last["last_intel"] = now
                except Exception:
                    failures.append("threat_intel")
            write_document("snapshot",export_state(local))
            last["last_completed"] = time.time()
            write_document("sync_schedule",last)
            last["failed_jobs"] = failures
            write_document("sync_schedule",last)
            audit("telemetry_sync",502 if failures else 200)
            return True
        finally:
            bound_store.reset(token)


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
