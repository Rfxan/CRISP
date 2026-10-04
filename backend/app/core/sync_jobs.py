"""Bounded sync jobs: network work runs outside the workspace database lock.

Job records are durable and tenant-scoped. A workspace edit during retrieval
invalidates the result instead of allowing an old snapshot to overwrite it.
"""
import copy
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from fastapi import HTTPException
from app.core.tenancy import tenant_transaction, principal_context, document_buffer, read_document, write_document, audit
from app.core.state_proxy import bound_store, export_state, import_state
from app.engine.model import digest

job_deadline = ContextVar("sync_deadline", default=float("inf"))
job_progress = ContextVar("sync_progress", default=lambda _: None)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="crisp-sync")
_slots = threading.BoundedSemaphore(4)
MAX_AGE = 300
KINDS = {"all", "telemetry", "connections", "intel", "wazuh", "indexer", "iam"}
TERMINAL = {"COMPLETED", "DEGRADED", "FAILED", "SUPERSEDED", "CANCELLED"}


def job_state(job_id):
    job = read_document("sync_job", {})
    if job.get("id") != job_id:
        raise HTTPException(404, "Sync job not found in this workspace")
    if job.get("status") not in TERMINAL and time.time() - job.get("updated_at", 0) > MAX_AGE:
        job.update(status="FAILED", message="Sync was interrupted or exceeded its time limit. Start a new sync.")
        write_document("sync_job", job)
    return job


def enqueue(request, kind):
    if kind not in KINDS:
        raise HTTPException(422, "Unknown sync type")
    identity = principal_context.get()
    if not identity:
        raise HTTPException(503, "Workspace storage unavailable")
    previous = read_document("sync_job", {})
    if previous.get("status") not in TERMINAL and time.time()-previous.get("updated_at", 0) < MAX_AGE:
        if previous.get("kind") != kind:
            raise HTTPException(409, "Another synchronization is running. Wait for it to finish before starting a different sync.")
        return previous
    if not _slots.acquire(blocking=False):
        raise HTTPException(503, "Sync queue busy; retry shortly", headers={"Retry-After": "5"})
    now = time.time()
    job = {"id": uuid.uuid4().hex, "kind": kind, "status": "QUEUED", "created_at": now,
           "updated_at": now, "message": "Waiting for a sync worker", "job_results": {}}
    write_document("sync_job", job)
    # TenantMiddleware dispatches only after a successful durable commit.
    request.state.sync_submission = (copy.deepcopy(identity), job["id"])
    return job


def submit(identity, job_id):
    _executor.submit(run_job, identity, job_id)


def abandon_submission():
    _slots.release()


def run_job(identity, job_id):
    from app.api import routes
    tokens = []
    try:
        with tenant_transaction(identity):
            job = job_state(job_id)
            if job["status"] != "QUEUED":
                return
            job.update(status="RUNNING", updated_at=time.time(), message="Retrieving telemetry")
            write_document("sync_job", job)
            docs = {key: read_document(key) for key in ("snapshot", "connections", "sync_state", "run_history", "intel_cursor")}
        local = routes.SnapshotStore()
        import_state(local, docs["snapshot"])
        original = digest(local.current_snapshot)
        original_connections = digest(docs["connections"])
        staged = copy.deepcopy(docs)
        staged["connections"] = staged.get("connections") or {}
        staged["sync_state"] = staged.get("sync_state") or {}
        staged["run_history"] = staged.get("run_history") or []

        def progress(message):
            with tenant_transaction(identity):
                current = job_state(job_id)
                if current["status"] == "CANCELLED":
                    raise RuntimeError("Sync cancelled")
                current.update(message=message, updated_at=time.time())
                write_document("sync_job", current)

        tokens = [(principal_context, principal_context.set(identity)),
                  (document_buffer, document_buffer.set(staged)),
                  (bound_store, bound_store.set(local)),
                  (job_deadline, job_deadline.set(time.monotonic()+180)),
                  (job_progress, job_progress.set(progress))]
        operations = {
            "all": routes.trigger_sync_all, "connections": routes.refresh_connections,
            "telemetry": lambda: routes.trigger_sync_all(include_intel=False),
            "intel": local.sync_live_threat_intel, "wazuh": routes.sync_wazuh_telemetry,
            "indexer": routes.sync_wazuh_indexer, "iam": routes.sync_iam_telemetry}
        try:
            result = operations[job["kind"]]()
        except HTTPException:
            result = {"status": "FAILED", "message": "Connector failed. Check its saved credentials and endpoint.",
                      "sync_state": staged["sync_state"]}
        staged["snapshot"] = export_state(local)
        with tenant_transaction(identity):
            current = job_state(job_id)
            latest = routes.SnapshotStore()
            import_state(latest, read_document("snapshot"))
            if current["status"] == "CANCELLED":
                return
            if digest(latest.current_snapshot) != original or digest(read_document("connections")) != original_connections:
                current.update(status="SUPERSEDED", message="Workspace changed during sync. Run sync again to update the new data.")
            else:
                for key, value in staged.items():
                    if value is not None:
                        write_document(key, value)
                status = result.get("status", "COMPLETED")
                if job["kind"] == "connections":
                    status = "DEGRADED" if any(not r.get("success") for r in result.get("results", {}).values()) else "COMPLETED"
                if status not in TERMINAL:
                    status = "COMPLETED"
                current.update(status=status, result=result, job_results=result.get("job_results", {}),
                               message="Sync finished" if status == "COMPLETED" else "Sync finished with unavailable or stale sources. Review connector and feed results.")
                audit("sync_job", 200, docs["snapshot"], staged["snapshot"])
            current["updated_at"] = time.time()
            write_document("sync_job", current)
    except Exception:
        logging.getLogger(__name__).exception("Sync job failed")
        try:
            with tenant_transaction(identity):
                current = job_state(job_id)
                if current["status"] != "CANCELLED":
                    current.update(status="FAILED", updated_at=time.time(), message="Sync could not finish. Retry or review the connection settings.")
                    write_document("sync_job", current)
        except Exception:
            logging.getLogger(__name__).error("Unable to persist sync failure")
    finally:
        for context, token in reversed(tokens):
            context.reset(token)
        _slots.release()
