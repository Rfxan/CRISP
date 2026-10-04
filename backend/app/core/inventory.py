"""Canonical inventory identifiers and explicit, non-verified source provenance."""


def normalize_inventory(snapshot):
    services = {}
    for row in snapshot.get("services", []):
        sid = str(row.get("id") or row.get("service_id") or "").strip()
        if not sid:
            continue
        candidate = dict(row, id=sid, service_id=sid)
        if sid not in services:
            services[sid] = candidate
        else:
            # Legacy CRUD appended generic duplicates. Keep established financial
            # context, filling only missing values from the duplicate.
            for key, value in candidate.items():
                if services[sid].get(key) in (None, ""):
                    services[sid][key] = value
    snapshot["services"] = list(services.values())
    for asset in snapshot.get("assets", []):
        asset.setdefault("origin", "synthetic" if snapshot.get("demo_mode") else "unknown")
        # An upload or user declaration does not independently verify a lab.
        asset["is_real_lab_asset"] = False
    return snapshot
