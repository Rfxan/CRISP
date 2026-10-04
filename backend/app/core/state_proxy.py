"""Bind the legacy store facade to an isolated store for the current request."""
from contextvars import ContextVar

bound_store = ContextVar("bound_store", default=None)


class StoreProxy:
    def __init__(self, factory):
        object.__setattr__(self, "_factory", factory)
        object.__setattr__(self, "_local", factory())

    def _target(self):
        return bound_store.get() or object.__getattribute__(self, "_local")

    def __getattr__(self, name):
        return getattr(self._target(), name)

    def __setattr__(self, name, value):
        setattr(self._target(), name, value)

    def __delattr__(self, name):
        delattr(self._target(), name)

    def __dir__(self):
        return sorted(set(object.__dir__(self)) | set(dir(self._target())))


def export_state(store):
    return {name:getattr(store,name) for name in ("current_snapshot", "telemetry_history", "has_real_siem_sync",
             "telemetry_source", "run_metadata", "run_sequence", "snapshot_history", "cached_summary", "last_state_signature")}


def import_state(store, data):
    for name,value in (data or {}).items():
        if name in ("current_snapshot", "telemetry_history", "has_real_siem_sync", "telemetry_source",
                    "run_metadata", "run_sequence", "snapshot_history", "cached_summary", "last_state_signature"):
            setattr(store,name,value)
    from app.core.inventory import normalize_inventory
    normalize_inventory(store.current_snapshot)
    store._optimizer_cache = None
