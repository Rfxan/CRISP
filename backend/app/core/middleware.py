import os
import sqlite3
import anyio
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.deployment import production
from app.core.tenancy import connect, begin_transaction, StateStoreUnavailable, principal_context, transaction_context, read_document, write_document, audit
from app.core.state_proxy import bound_store, import_state, export_state
from app.core.web_security import read_only_demo, guest_mode
from app.core.guest_workspace import remember_workspace, enforce_limits


class TenantMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path in ("/health", "/api/health", "/api/security/capabilities") or request.method == "OPTIONS":
            return await call_next(request)
        identity = getattr(request.state, "guest_identity", None)
        if guest_mode() and not identity:
            return JSONResponse({"detail": "Browser workspace unavailable"}, 403)
        identity = identity or {"tenant": "local", "subject": "local-workspace"}
        # Unit tests can explicitly use the original in-memory facade. Production cannot.
        if os.getenv("CRISP_TESTING") == "1" and not production():
            return await call_next(request)
        db = None
        try:
            db = await anyio.to_thread.run_sync(connect)
            await anyio.to_thread.run_sync(lambda: begin_transaction(db, identity["tenant"]))
            if identity["tenant"].startswith("guest:"):
                remember_workspace(db, identity)
        except (sqlite3.OperationalError, StateStoreUnavailable):
            if db is not None:
                db.close()
            return JSONResponse({"detail":"State store busy or unavailable; retry the request"},503)
        pt = principal_context.set(identity)
        tt = transaction_context.set(db)
        from app.api.routes import SnapshotStore
        local = SnapshotStore()
        before = read_document("snapshot")
        if before:
            import_state(local, before)
        st = bound_store.set(local)
        submitted = False
        try:
            response = await call_next(request)
            # Connector failures clear stale coverage; persist that evidence even when
            # the connector returns 502. Other rejected mutations roll back atomically.
            connector_failure = response.status_code == 502 and request.url.path in (
                "/api/ingest/wazuh-sync", "/api/ingest/wazuh-indexer-sync", "/api/ingest/iam-sync")
            if read_only_demo():
                # Counterfactuals and lazy analytics may populate transient state,
                # but public requests must never persist it or append audit rows.
                db.rollback()
            elif response.status_code < 400 or connector_failure:
                try:
                    enforce_limits(local.current_snapshot)
                except HTTPException as exc:
                    db.rollback()
                    return JSONResponse({"detail": exc.detail}, exc.status_code)
                after = export_state(local)
                write_document("snapshot", after)
                if not identity["tenant"].startswith("guest:") or request.method not in ("GET", "HEAD"):
                    audit(f"{request.method} {request.url.path}",response.status_code,before,after)
                db.commit()
                submission = getattr(request.state, "sync_submission", None)
                if submission:
                    from app.core.sync_jobs import submit
                    submit(*submission)
                    submitted = True
            else:
                db.rollback()
                await anyio.to_thread.run_sync(lambda: begin_transaction(db, identity["tenant"]))
                audit(f"{request.method} {request.url.path}", response.status_code)
                db.commit()
            return response
        except Exception:
            db.rollback()
            raise
        finally:
            if getattr(request.state, "sync_submission", None) and not submitted:
                from app.core.sync_jobs import abandon_submission
                abandon_submission()
            bound_store.reset(st); transaction_context.reset(tt); principal_context.reset(pt)
            db.close()
