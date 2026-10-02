from fastapi import APIRouter, HTTPException, Query, Response, Body, UploadFile, File, Form
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import json
import copy
import xml.etree.ElementTree as ET
import csv
import io
import re
import logging
import time
import hashlib
import numpy as np
from datetime import datetime, timezone, timedelta
import requests

from app.core.config import DATA_DIR, settings
from app.core.sync_state import sync_state_manager
from app.engine.fair_engine import FAIREngine
from app.engine.model import digest, assumptions, MODEL_VERSION
from app.core.tenancy import active as tenant_active, read_document, write_document, principal_context, transaction_context
from app.engine.optimizer import InvestmentOptimizer
from app.engine.whatif import WhatIfSimulator
from app.engine.sensitivity import SensitivityAnalyzer
from app.compliance.catalog import ControlCatalog
from app.compliance.framework_engine import FrameworkEngine
from app.compliance.report_generator import ReportGenerator
from app.compliance.evidence_report import EvidenceReportGenerator
from app.ai.decision_support import DecisionSupportAI
from app.ai.anomaly import TelemetryAnomalyDetector, ANOMALY_LABEL
from app.connectors.openvas import OpenVASConnector
from app.connectors.wazuh import WazuhConnector
from app.connectors.nessus import NessusConnector
from app.connectors.iam import KeycloakConnector
from app.connectors.cspm import ProwlerConnector
from app.connectors.threat_intel import ThreatIntelFeed
from app.connectors.format_detector import detect_scan_format
from app.connectors.defender import DefenderEDRConnector
from app.connectors.sniffer import detect_structure
from app.connectors.generic import GenericVendorConnector
from app.core.connections_store import connections_store
from app.core.sync_state import sync_state_manager
from app.core.run_history import run_history_manager
from app.ai.llm_config_store import llm_config_store
from app.ai.llm_service import llm_service

router = APIRouter()
logger = logging.getLogger(__name__)


def _is_better_control_state(candidate: Dict[str, Any], current: Dict[str, Any]) -> bool:
    """
    Evaluates whether candidate should replace current for the same control_id:
    1. Most recent last_checked timestamp
    2. Non-None coverage_pct over None coverage_pct
    3. User-set or live evidence over 'Not Connected' / None
    4. Explicit user assumption
    5. Default keep-last rule
    """
    # 1. Compare last_checked timestamps
    cand_lc = candidate.get("last_checked")
    curr_lc = current.get("last_checked")
    if cand_lc and not curr_lc:
        return True
    if curr_lc and not cand_lc:
        return False
    if cand_lc and curr_lc:
        try:
            cand_dt = datetime.fromisoformat(str(cand_lc).replace("Z", "+00:00"))
            curr_dt = datetime.fromisoformat(str(curr_lc).replace("Z", "+00:00"))
            if cand_dt > curr_dt:
                return True
            elif cand_dt < curr_dt:
                return False
        except Exception:
            if str(cand_lc) > str(curr_lc):
                return True
            elif str(cand_lc) < str(curr_lc):
                return False

    # 2. Prefer non-None coverage_pct
    cand_cov = candidate.get("coverage_pct")
    curr_cov = current.get("coverage_pct")
    if cand_cov is not None and curr_cov is None:
        return True
    if curr_cov is not None and cand_cov is None:
        return False

    # 3. Prefer connected evidence over 'Not Connected' / empty
    cand_ev = str(candidate.get("evidence_ref") or "").strip()
    curr_ev = str(current.get("evidence_ref") or "").strip()
    cand_connected = bool(cand_ev and cand_ev.lower() not in ("not connected", "none", ""))
    curr_connected = bool(curr_ev and curr_ev.lower() not in ("not connected", "none", ""))
    if cand_connected and not curr_connected:
        return True
    if curr_connected and not cand_connected:
        return False

    # 4. Prefer explicit user assumption
    if candidate.get("is_user_assumed") and not current.get("is_user_assumed"):
        return True

    # 5. Default keep-last rule
    return True


def dedupe_control_states(control_states: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], int]:
    """
    Collapses control_state to unique control_ids (keep the entry with the most recent
    last_checked, or prefer non-None coverage_pct).
    Logs how many duplicates were removed.
    """
    if not control_states:
        return [], 0
    unique_map: Dict[str, Dict[str, Any]] = {}
    for cs in control_states:
        cid = cs.get("control_id")
        if not cid:
            continue
        if cid not in unique_map:
            unique_map[cid] = cs
        else:
            if _is_better_control_state(cs, unique_map[cid]):
                unique_map[cid] = cs
    deduped = list(unique_map.values())
    removed = len(control_states) - len(deduped)
    if removed > 0:
        logger.info(f"Deduplicated control_state: removed {removed} duplicate control state(s). Retained {len(deduped)} unique controls.")
    return deduped, removed


# In-memory snapshot manager — starts EMPTY until user uploads real data
class SnapshotStore:
    def __init__(self):
        self.snapshot_history = []
        self._init_empty()

    def dedupe_control_state(self) -> int:
        """Collapses control_state to unique control_ids and returns count of removed duplicates."""
        raw_controls = self.current_snapshot.get("control_state", [])
        deduped, removed = dedupe_control_states(raw_controls)
        self.current_snapshot["control_state"] = deduped
        return removed

    def ensure_catalog_controls(self) -> int:
        """
        Ensures all catalog controls exist in control_state.
        If any are missing, appends them as NO DATA defaults and dedupes.
        """
        default_scopes = {
            "CTRL-MFA-01": "Privileged Accounts",
            "CTRL-EDR-01": "All Endpoints",
            "CTRL-PATCH-01": "Internet-Facing & Tier-1 Core Servers",
            "CTRL-ENC-01": "Primary Database Repositories",
            "CTRL-WAF-01": "DMZ Edge & Customer Ingress Ports",
            "CTRL-SEG-01": "Payment Switch & Core Banking VLANs",
            "CTRL-BKP-01": "Critical CBS & Payment Databases",
            "CTRL-SIEM-01": "Enterprise-wide telemetry sources",
            "CTRL-PAM-01": "Domain Controllers & Database Root logins",
            "CTRL-DLP-01": "Core Banking and Customer Support endpoints",
            "CTRL-API-01": "External Partner UPI & Banking APIs",
            "CTRL-IR-01": "Organization Wide"
        }
        existing = self.current_snapshot.get("control_state", [])
        existing_ids = {c.get("control_id") for c in existing if c.get("control_id")}
        for ctrl in self.controls_catalog:
            cid = ctrl.get("id")
            if cid and cid not in existing_ids:
                existing.append({
                    "control_id": cid,
                    "asset_scope": default_scopes.get(cid, "Privileged Accounts" if "MFA" in cid else ("All Endpoints" if "EDR" in cid else "Enterprise Scope")),
                    "coverage_pct": None,
                    "evidence_ref": "Not Connected",
                    "last_checked": None,
                    "is_simulated": False,
                    "is_user_assumed": False
                })
        self.current_snapshot["control_state"] = existing
        return self.dedupe_control_state()

    def load_seed(self):
        """Loads seed_snapshot.json, ensures methodology catalog controls are present, dedupes, and recomputes."""
        seed_path = DATA_DIR / "seed_snapshot.json"
        with open(seed_path, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
        snapshot["controls_catalog"] = self.controls_catalog
        snapshot["demo_mode"] = True
        self.current_snapshot = snapshot
        self.ensure_catalog_controls()
        self.cached_summary = None
        self.last_state_signature = None
        return self.check_and_recompute(trigger="load_seed", force=True)

    def _init_empty(self):
        """
        Initializes an empty snapshot. The application starts with ZERO company
        data — no assets, no findings, no control_state, no organization profile.
        Scenarios and controls_catalog are platform methodology (not company data)
        and are always loaded.
        """
        # Load platform methodology: scenarios
        scenarios_path = DATA_DIR / "scenarios.json"
        with open(scenarios_path, "r", encoding="utf-8") as f:
            scenarios = json.load(f)

        # Load platform methodology: controls catalog
        catalog_path = DATA_DIR / "controls_catalog.json"
        with open(catalog_path, "r", encoding="utf-8") as f:
            self.controls_catalog = json.load(f)

        default_scopes = {
            "CTRL-MFA-01": "Privileged Accounts",
            "CTRL-EDR-01": "All Endpoints",
            "CTRL-PATCH-01": "Internet-Facing & Tier-1 Core Servers",
            "CTRL-ENC-01": "Primary Database Repositories",
            "CTRL-WAF-01": "DMZ Edge & Customer Ingress Ports",
            "CTRL-SEG-01": "Payment Switch & Core Banking VLANs",
            "CTRL-BKP-01": "Critical CBS & Payment Databases",
            "CTRL-SIEM-01": "Enterprise-wide telemetry sources",
            "CTRL-PAM-01": "Domain Controllers & Database Root logins",
            "CTRL-DLP-01": "Core Banking and Customer Support endpoints",
            "CTRL-API-01": "External Partner UPI & Banking APIs",
            "CTRL-IR-01": "Organization Wide"
        }
        initial_controls = [
            {
                "control_id": ctrl["id"],
                "asset_scope": default_scopes.get(ctrl["id"], "Privileged Accounts" if "MFA" in ctrl["id"] else ("All Endpoints" if "EDR" in ctrl["id"] else "Enterprise Scope")),
                "coverage_pct": None,
                "evidence_ref": "Not Connected",
                "last_checked": None,
                "is_simulated": False,
                "is_user_assumed": False
            }
            for ctrl in self.controls_catalog
        ]

        # Empty snapshot — methodology controls present; company assets/findings start empty
        self.current_snapshot = {
            "snapshot_id": None,
            "organization": None,
            "timestamp": None,
            "assets": [],
            "services": [],
            "findings": [],
            "cve_intel": {},
            "wazuh_telemetry": {},
            "control_state": initial_controls,
            "scenarios": scenarios,
            "controls_catalog": self.controls_catalog
        }
        self.dedupe_control_state()

        self.engine = FAIREngine(trials=5000, seed=settings.DEFAULT_SEED)
        self.whatif_sim = WhatIfSimulator(self.engine)
        self.sensitivity = SensitivityAnalyzer(self.engine)
        self.framework_engine = FrameworkEngine(ControlCatalog())
        self.ai = DecisionSupportAI()
        self.threat_intel = ThreatIntelFeed()
        self.anomaly_detector = TelemetryAnomalyDetector(contamination=0.1, random_state=settings.DEFAULT_SEED)
        self.telemetry_history: List[Dict[str, Any]] = []
        self.has_real_siem_sync: bool = False
        self.telemetry_source: str = "none"
        self.cached_summary = None
        self.last_state_signature = None
        self.run_sequence = 0
        self._optimizer_cache = None
        self.run_metadata = {
            "run_id": None,
            "recomputed": True,
            "recompute_reason": "Platform initialization",
            "last_recompute_at": datetime.now(timezone.utc).isoformat(),
            "skip_reason": None,
            "changes_detected": True
        }

    def _is_empty_state(self, summary: Dict[str, Any] = None) -> bool:
        """Returns True if summary represents a NO_DATA or NO_FINDINGS state."""
        s = summary or self.cached_summary
        if not s:
            return True
        return s.get("org", {}).get("eal") is None

    def get_telemetry_anomalies(self) -> Dict[str, Any]:
        """
        Runs unsupervised Isolation Forest over accumulated per-agent telemetry history.
        Returns 'insufficient_baseline_data' if fewer than MIN_BASELINE_SAMPLES exist.
        Never calls _init_demo_telemetry_history() when a SIEM connection exists with a successful real sync.
        Demo seeding is only acceptable with zero connections configured, AND then only behind a prominent DEMO DATA badge.
        Until 5 real windows exist, shows 'Building baseline: N/5 windows · Source: Wazuh Live API'.
        """
        conn = connections_store.get_connection("siem")
        has_siem_conn = bool(conn and conn.get("base_url") and conn.get("connected", True))
        has_real_sync = getattr(self, "has_real_siem_sync", False) or (self.current_snapshot.get("wazuh_telemetry", {}).get("source") == "Wazuh Live API")
        is_mock_sync = (self.current_snapshot.get("wazuh_telemetry", {}).get("source") == "Wazuh Telemetry Mock")

        if has_siem_conn or has_real_sync:
            # SIEM connection exists or real sync has succeeded: NEVER fabricate demo data
            current_windows = len(self.telemetry_history)
            if current_windows < 5:
                return {
                    "status": "insufficient_baseline_data",
                    "message": f"Building baseline: {current_windows}/5 windows · Source: Wazuh Live API",
                    "total_windows": current_windows,
                    "history_windows_count": current_windows,
                    "required_windows": 5,
                    "min_required_windows": 5,
                    "anomalies_detected": 0,
                    "signals": [],
                    "results": [],
                    "model": "IsolationForest (scikit-learn)",
                    "label": ANOMALY_LABEL,
                    "is_insufficient": True,
                    "source": "Wazuh Live API",
                    "is_demo": False
                }
            res = self.anomaly_detector.detect_anomalies(self.telemetry_history)
            res["source"] = "Wazuh Live API"
            res["is_demo"] = False
            res["total_windows"] = current_windows
            res["history_windows_count"] = current_windows
            res["required_windows"] = 5
            res["min_required_windows"] = 5
            for sig in res.get("signals", []):
                sig["source"] = "Wazuh Live API"
                sig["is_demo"] = False
            for r in res.get("results", []):
                r["source"] = "Wazuh Live API"
                r["is_demo"] = False
            return res

        if is_mock_sync:
            # Mock sync path (?simulate=true)
            if not self.telemetry_history:
                self._init_demo_telemetry_history(source="Wazuh Telemetry Mock")
            res = self.anomaly_detector.detect_anomalies(self.telemetry_history)
            res["source"] = "Wazuh Telemetry Mock"
            res["is_demo"] = True
            res["is_simulated"] = True
            res["total_windows"] = len(self.telemetry_history)
            res["history_windows_count"] = len(self.telemetry_history)
            res["required_windows"] = 5
            res["min_required_windows"] = 5
            for sig in res.get("signals", []):
                sig["source"] = "Wazuh Telemetry Mock"
                sig["is_demo"] = True
                sig["is_simulated"] = True
            for r in res.get("results", []):
                r["source"] = "Wazuh Telemetry Mock"
                r["is_demo"] = True
                r["is_simulated"] = True
            return res

        # Zero connections configured path
        if not self.current_snapshot.get("demo_mode") and not self.telemetry_history:
            return {
                "status": "insufficient_baseline_data",
                "message": "insufficient baseline data: no telemetry history available in empty state",
                "total_windows": 0,
                "history_windows_count": 0,
                "required_windows": 5,
                "min_required_windows": 5,
                "anomalies_detected": 0,
                "signals": [],
                "results": [],
                "model": "IsolationForest (scikit-learn)",
                "label": ANOMALY_LABEL,
                "is_insufficient": True,
                "source": "none",
                "is_demo": False
            }

        # Demo seeding is only acceptable with zero connections configured
        if not self.telemetry_history:
            self._init_demo_telemetry_history(source="demo fixture")

        res = self.anomaly_detector.detect_anomalies(self.telemetry_history)
        res["source"] = "demo fixture"
        res["is_demo"] = True
        res["total_windows"] = len(self.telemetry_history)
        res["history_windows_count"] = len(self.telemetry_history)
        res["required_windows"] = 5
        res["min_required_windows"] = 5
        for sig in res.get("signals", []):
            sig["source"] = "demo fixture"
            sig["is_demo"] = True
        for r in res.get("results", []):
            r["source"] = "demo fixture"
            r["is_demo"] = True
        return res

    def _init_demo_telemetry_history(self, source: str = "demo fixture"):
        """Initializes a realistic 8-window baseline telemetry history for demo assets."""
        import random
        rng = random.Random(42)
        assets = ["AST-PAY-DB-01", "AST-PAY-GW-01", "AST-NETBANK-APP-01", "AST-AD-DC-01", "AST-CRM-APP-01", "AST-CORE-DB-01"]
        base_history = []
        for i in range(8):
            for aid in assets:
                base_history.append({
                    "agent_id": aid,
                    "agent_name": f"wazuh-{aid.lower()}",
                    "timestamp": f"2026-09-29T{10+i:02d}:00:00Z",
                    "event_volume": rng.randint(80, 160),
                    "auth_failures": rng.randint(1, 4),
                    "total_alerts": rng.randint(5, 15),
                    "high_severity_alerts": 0 if rng.random() > 0.15 else 1,
                    "source": source,
                    "is_demo": True
                })
        self.telemetry_history = base_history
        self.telemetry_source = source

    def record_history_point(self, eal: float):
        if eal is None:
            return  # Don't record history for empty states
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self.snapshot_history and self.snapshot_history[-1]["date"] == now_str:
            self.snapshot_history[-1]["eal"] = eal
        else:
            self.snapshot_history.append({"date": now_str, "eal": eal, "label": "Telemetry Ingestion Update"})

    def compute_state_signature(self) -> str:
        # Exclude clocks, not substantive business/evidence/model inputs.
        volatile = {"timestamp", "last_checked", "last_seen", "first_seen", "last_sync", "last_sync_at", "completed_at", "synced_at"}
        def stable(value):
            if isinstance(value, dict):
                return {k: stable(v) for k, v in value.items() if k not in volatile}
            if isinstance(value, list):
                return [stable(v) for v in value]
            return value
        return digest({"snapshot": stable(self.current_snapshot),
                       "assumptions": assumptions(self.current_snapshot), "model": MODEL_VERSION,
                       "trials": self.engine.trials, "seed": self.engine.seed})

    def get_optimizer(self, summary=None):
        summary = summary or self.get_summary()
        key = self.compute_state_signature()
        cached = getattr(self, "_optimizer_cache", None)
        if cached is None or cached[0] != key:
            optimizer = InvestmentOptimizer(self.controls_catalog, self.current_snapshot["findings"],
                self.current_snapshot["cve_intel"], snapshot=self.current_snapshot,
                engine=self.engine, seed=settings.DEFAULT_SEED, baseline=summary)
            self._optimizer_cache = (key, optimizer)
        return self._optimizer_cache[1]

    def merge_findings(self, findings):
        def key(f):
            return (f.get("asset_id"), f.get("cve_id") or f.get("issue_type") or f.get("title"),
                    str(f.get("port")), f.get("source"))
        existing = {key(f): f for f in self.current_snapshot.get("findings", [])}
        for f in findings:
            k = key(f)
            if k in existing:
                old_id = existing[k]["id"]
                existing[k].update(f)
                existing[k]["id"] = old_id
            else:
                self.current_snapshot.setdefault("findings", []).append(f)
                existing[k] = f
        known = {a.get("id") for a in self.current_snapshot.get("assets", [])}
        for f in findings:
            aid = f.get("asset_id")
            if aid and aid not in known:
                self.current_snapshot.setdefault("assets", []).append({"id": aid, "name": aid,
                    "criticality_1_5": None, "has_business_context": False, "is_real_lab_asset": True,
                    "records_count": None, "revenue_per_hour": None})
                known.add(aid)
        self.current_snapshot["assessment_state"] = {"status": "completed",
            "source": "Imported scan", "completed_at": datetime.now(timezone.utc).isoformat()}

    def check_and_recompute(self, trigger: str = "manual", force: bool = False) -> Dict[str, Any]:
        """
        Diffs against previous snapshot state.
        If findings/assets/controls changed (or force=True or cached_summary is None):
            - Triggers a full engine recompute automatically
            - Mints a new run_id
            - Updates run_metadata with recomputed=True
        If nothing changed:
            - Skips recompute (logs why)
            - Retains existing run_id
            - Updates run_metadata with recomputed=False and skip_reason
        """
        self.dedupe_control_state()
        current_sig = self.compute_state_signature()
        state_changed = (self.last_state_signature is None or current_sig != self.last_state_signature)

        if state_changed or force or self.cached_summary is None:
            self.last_state_signature = current_sig
            self.run_sequence += 1
            now_iso = datetime.now(timezone.utc).isoformat()

            # Execute full FAIR engine simulation
            summary = self.engine.run(self.current_snapshot, seed=settings.DEFAULT_SEED)

            # Mint unique sequential run_id
            new_run_id = summary.get("run_id")
            summary["run_id"] = new_run_id

            eal = summary.get("org", {}).get("eal")
            self.record_history_point(eal)

            if eal is not None:
                run_history_manager.append_run(
                    run_id=new_run_id,
                    timestamp=now_iso,
                    eal=eal,
                    var95=summary.get("org", {}).get("var95"),
                    asset_count=len(self.current_snapshot.get("assets", [])),
                    finding_count=len(self.current_snapshot.get("findings", [])),
                    assumptions_version=summary.get("assumptions_version", settings.ASSUMPTIONS_VERSION)
                )

            self.run_metadata = {
                "run_id": new_run_id,
                "recomputed": True,
                "recompute_reason": f"State change detected via {trigger}",
                "last_recompute_at": now_iso,
                "skip_reason": None,
                "changes_detected": True,
                "state_signature": current_sig[:12]
            }
            summary["run_metadata"] = self.run_metadata
            self.cached_summary = summary
            logger.info(f"FAIR Engine recomputed via {trigger}. Minted new {new_run_id} (sig: {current_sig[:8]}).")
            return summary
        else:
            current_run_id = self.cached_summary.get("run_id") if self.cached_summary else f"RUN-{settings.DEFAULT_SEED}-00000"
            skip_msg = f"No changes detected in assets, findings, or controls during {trigger} (signature: {current_sig[:8]})"
            logger.info(f"Sync ({trigger}): {skip_msg}. Skipping engine recompute. Retaining run_id {current_run_id}.")
            self.run_metadata = {
                "run_id": current_run_id,
                "recomputed": False,
                "recompute_reason": None,
                "last_recompute_at": self.run_metadata.get("last_recompute_at"),
                "skip_reason": skip_msg,
                "changes_detected": False,
                "state_signature": current_sig[:12]
            }
            if self.cached_summary:
                self.cached_summary["run_metadata"] = self.run_metadata
            return self.cached_summary

    def get_summary(self, force_refresh: bool = False) -> Dict[str, Any]:
        if self.cached_summary is None or force_refresh or self.compute_state_signature() != self.last_state_signature:
            return self.check_and_recompute(trigger="get_summary", force=force_refresh)
        return self.cached_summary

    def inject_cve_event(self, cve_id: str, asset_id: str, severity: str = "Critical", epss: float = 0.98) -> Dict[str, Any]:
        """Injects a new KEV-listed zero day onto an asset for live demo."""
        if not self.current_snapshot.get("assets"):
            raise ValueError("Cannot inject events — no assets have been loaded yet.")
        new_fnd = {
            "id": f"FND-LIVE-{len(self.current_snapshot['findings'])+1:03d}",
            "asset_id": asset_id,
            "cve_id": cve_id,
            "cvss": 10.0,
            "severity": severity,
            "port": 443,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "source": "CISA KEV Live Feed Trigger"
        }
        self.current_snapshot["findings"].append(new_fnd)
        self.current_snapshot["cve_intel"][cve_id] = {
            "cve_id": cve_id,
            "description": f"Zero-day RCE on {asset_id} (CISA KEV live feed addition)",
            "epss": epss,
            "epss_percentile": 0.999,
            "in_kev": True,
            "exploit_public": True,
            "published": datetime.now(timezone.utc).strftime("%Y-%m-%d")
        }
        
        old_eal = self.cached_summary["org"]["eal"] if self.cached_summary and self.cached_summary["org"].get("eal") else 0.0
        summary = self.check_and_recompute(trigger="inject_cve_event", force=True)
        new_eal = summary["org"]["eal"]

        return {
            "event": "KEV_INJECTION_SUCCESS",
            "injected_cve": cve_id,
            "target_asset": asset_id,
            "previous_eal": old_eal,
            "new_eal": new_eal,
            "jump_amount": round(new_eal - old_eal, 2),
            "run_id": summary["run_id"]
        }

    def enrich_findings_intel(self, findings: List[Dict[str, Any]]):
        """
        Enriches findings with live EPSS, NVD, and CISA KEV intelligence.
        Surfaces per-finding provenance and KEV exploitability label.
        """
        cve_intel = self.current_snapshot.get("cve_intel", {})
        kev_res = self.threat_intel.fetch_cisa_kev()

        for f in findings:
            cve = f.get("cve_id")
            if cve:
                cve_clean = cve.strip().upper()
                f["cve_id"] = cve_clean
                if cve_clean not in cve_intel or "provenance" not in cve_intel[cve_clean]:
                    enriched = self.threat_intel.enrich_cve(cve_clean, kev_catalog=kev_res, local_cache=cve_intel)
                    cve_intel[cve_clean] = enriched
                intel = cve_intel[cve_clean]
                f["in_kev"] = intel.get("in_kev", False)
                f["exploitability_label"] = intel.get("exploitability_label", "Standard exploit likelihood")
                f["threat_intel_provenance"] = intel.get("provenance")

    def sync_live_threat_intel(self) -> Dict[str, Any]:
        """
        Daily / on-demand synchronization of authoritative threat intelligence feeds:
        1. CISA KEV catalog (downloads active exploitation set)
        2. FIRST EPSS (queries live probability & percentile)
        3. NIST NVD API v2 (fetches CVSS v3.x score/vector, description, published date)
        Surfaces per-finding provenance and updates FAIR risk quantification.
        """
        cve_intel = self.current_snapshot.get("cve_intel", {})
        findings = self.current_snapshot.get("findings", [])
        unique_cves = list({f["cve_id"].strip().upper() for f in findings if f.get("cve_id")})

        # 1. Download CISA KEV catalog
        kev_res = self.threat_intel.fetch_cisa_kev(force_refresh=True)

        # 2. Enrich each unique CVE with EPSS and NVD v2
        updated = 0
        for cve in unique_cves:
            enriched = self.threat_intel.enrich_cve(cve, kev_catalog=kev_res, local_cache=cve_intel)
            cve_intel[cve] = enriched
            updated += 1

        # 3. Propagate to all findings
        for f in findings:
            cve = f.get("cve_id")
            if cve:
                cve_clean = cve.strip().upper()
                if cve_clean in cve_intel:
                    intel = cve_intel[cve_clean]
                    f["in_kev"] = intel.get("in_kev", False)
                    f["exploitability_label"] = intel.get("exploitability_label", "Standard exploit likelihood")
                    f["threat_intel_provenance"] = intel.get("provenance")

        # 4. Record to sync_state
        sync_record = sync_state_manager.record_sync(
            job_name="threat_intel",
            source="CISA KEV / NVD / EPSS",
            counts={
                "cves_queried": len(unique_cves),
                "cves_updated": updated,
                "kev_catalog_count": kev_res.get("count", 0),
                "assets": len(self.current_snapshot.get("assets", [])),
                "findings": len(findings)
            },
            status="ok",
            message=f"Enriched {updated} CVEs (KEV catalog: {kev_res.get('count', 0)} entries)"
        )

        # 5. Check and recompute only if data changed
        summary = self.check_and_recompute(trigger="sync_live_threat_intel")

        return {
            "status": "SYNCED",
            "cves_queried": len(unique_cves),
            "cves_updated": updated,
            "kev_catalog_count": kev_res.get("count", 0),
            "kev_status": kev_res.get("status", "unavailable"),
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "run_id": summary.get("run_id") if summary else None,
            "run_metadata": self.run_metadata,
            "sync_record": sync_record,
            "provenance_summary": {cve: cve_intel[cve].get("provenance") for cve in unique_cves if cve in cve_intel}
        }

    def sync_live_epss_and_kev(self) -> Dict[str, Any]:
        """Backward compatibility alias for sync_live_threat_intel."""
        return self.sync_live_threat_intel()

from app.core.state_proxy import StoreProxy
store = StoreProxy(SnapshotStore)


# Request Models
class SimulateRequest(BaseModel):
    actions: List[Dict[str, Any]]
    seed: int = Field(default=42, ge=0)

class OptimizeRequest(BaseModel):
    budget: float = Field(default=10_000_000.0, ge=0, allow_inf_nan=False)  # ₹1 Crore default
    constraints: Optional[Dict[str, Any]] = None

class AskRequest(BaseModel):
    question: str

class InjectEventRequest(BaseModel):
    cve_id: str = "CVE-2026-9999"
    asset_id: str = "AST-PAY-GW-01"
    severity: str = "Critical"
    epss: float = 0.98

class UpdateControlRequest(BaseModel):
    control_id: str
    coverage_pct: float = Field(ge=0, le=100, allow_inf_nan=False)

class UpdateControlsRequest(BaseModel):
    controls: List[UpdateControlRequest] = Field(min_length=1, max_length=1000)

class VendorSaveRequest(BaseModel):
    vendor_name: str
    format: str
    record_path: Optional[str] = ""
    field_mapping: Dict[str, Any]
    sample_file_used: Optional[str] = None

class ConnectionPayload(BaseModel):
    base_url: str
    username: Optional[str] = ""
    password: Optional[str] = ""

class LLMConfigPayload(BaseModel):
    provider: str
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: Optional[float] = 0.2
    enabled: Optional[bool] = True

class AddAssetRequest(BaseModel):
    id: Optional[str] = None
    asset_id: Optional[str] = None
    name: Optional[str] = None
    business_service_id: Optional[str] = None
    service: Optional[str] = None
    criticality_1_5: Optional[int] = None
    criticality: Optional[int] = None
    records_count: Optional[int] = 0
    records: Optional[int] = None
    revenue_per_hour: Optional[float] = 0.0
    internet_facing: Optional[bool] = False
    type: Optional[str] = "Server"
    owner: Optional[str] = None
    environment: Optional[str] = "Production"
    data_classification: Optional[str] = "Confidential"

class UpdateAssetRequest(BaseModel):
    name: Optional[str] = None
    business_service_id: Optional[str] = None
    service: Optional[str] = None
    criticality_1_5: Optional[int] = None
    criticality: Optional[int] = None
    records_count: Optional[int] = None
    records: Optional[int] = None
    revenue_per_hour: Optional[float] = None
    internet_facing: Optional[bool] = None
    type: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = None
    data_classification: Optional[str] = None


# --- API Endpoints matching Section 11 & Dynamic Ingestion ---

@router.get("/risk/summary")
def get_risk_summary(refresh: bool = False):
    """GET /risk/summary -> EAL, VaR95, tail, score, appetite headroom, trend"""
    summary = store.get_summary(force_refresh=refresh)

    # If no data loaded yet, pass through the structured empty-state response
    if store._is_empty_state(summary):
        return {
            "status": summary.get("status"),
            "message": summary.get("message"),
            "eal": None,
            "var95": None,
            "var99": None,
            "tail": None,
            "score": None,
            "drivers": [],
            "curve": [],
            "org": summary["org"],
            "loss_breakdown": {},
            "trend": run_history_manager.compute_trajectory(current_eal=None),
            "drivers_count": 0,
            "excluded_assets": summary.get("excluded_assets", []),
            "excluded_assets_count": summary.get("excluded_assets_count", 0),
            "run_id": summary.get("run_id"),
            "run_metadata": store.run_metadata,
            "sync_state": sync_state_manager.get_state(),
            "freshness": sync_state_manager.get_freshness_summary()
        }

    current_eal = summary["org"]["eal"]

    # Compute trend projection dynamically from actual recorded run history
    trend = run_history_manager.compute_trajectory(current_eal=current_eal)

    return {
        "run_id": summary["run_id"],
        "ts": summary["ts"],
        "seed": summary["seed"],
        "trials": summary["trials"],
        "assumptions_version": summary["assumptions_version"],
        "model_version": summary.get("model_version"),
        "snapshot_hash": summary.get("snapshot_hash"),
        "status": summary.get("status"),
        "explanation": summary.get("explanation"),
        "org": summary["org"],
        "loss_breakdown": summary["loss_breakdown"],
        "trend": trend,
        "drivers_count": len(summary["drivers"]),
        "excluded_assets": summary.get("excluded_assets", []),
        "excluded_assets_count": summary.get("excluded_assets_count", 0),
        "run_metadata": store.run_metadata,
        "sync_state": sync_state_manager.get_state(),
        "freshness": sync_state_manager.get_freshness_summary()
    }

@router.get("/risk/entities")
def get_risk_entities(level: str = Query("asset", pattern="^(org|business_unit|service|asset)$")):
    """GET /risk/entities?level=org|business_unit|service|asset"""
    summary = store.get_summary()
    if store._is_empty_state(summary):
        entities = summary.get("assets", []) if level == "asset" else ([summary["org"]] if level == "org" else [])
        return {"level": level, "entities": entities, "total": len(entities), "status": summary.get("status"), "excluded_assets": summary.get("excluded_assets", []), "excluded_assets_count": summary.get("excluded_assets_count", 0)}
    if level == "asset":
        return {"level": "asset", "entities": summary["assets"], "total": len(summary["assets"]), "excluded_assets": summary.get("excluded_assets", []), "excluded_assets_count": summary.get("excluded_assets_count", 0)}
    elif level == "service":
        return {"level": "service", "entities": summary["services"], "total": len(summary["services"])}
    elif level == "business_unit":
        # Group services dynamically into business units
        bu_map: Dict[str, float] = {}
        for s in summary["services"]:
            s_name = s.get("name", "")
            s_id = s.get("service_id", "")
            bu = s.get("business_unit") or "Unassigned business unit"

            bu_map[bu] = bu_map.get(bu, 0.0) + s.get("eal", 0.0)

        bu_entities = [{"name": name, "eal": round(total, 2)} for name, total in bu_map.items()]
        return {"level": "business_unit", "entities": bu_entities, "total": len(bu_entities)}
    else:
        return {"level": "org", "entities": [summary["org"]], "total": 1}

@router.get("/risk/drivers")
def get_risk_drivers():
    """GET /risk/drivers -> top contributors by marginal EAL + emerging threat signals"""
    summary = store.get_summary()
    anomaly_res = store.get_telemetry_anomalies()
    emerging_threats = anomaly_res.get("signals", [])

    if store._is_empty_state(summary):
        return {
            "run_id": None,
            "top_drivers": [],
            "choke_points": [],
            "emerging_threats": emerging_threats,
            "anomaly_detection": {
                "status": anomaly_res.get("status"),
                "model": "IsolationForest (scikit-learn)",
                "label": ANOMALY_LABEL,
                "message": anomaly_res.get("message"),
                "anomalies_detected": anomaly_res.get("anomalies_detected", 0),
                "source": anomaly_res.get("source"),
                "is_demo": anomaly_res.get("is_demo", False),
                "is_insufficient": anomaly_res.get("is_insufficient", False),
                "total_windows": anomaly_res.get("total_windows", 0),
                "history_windows_count": anomaly_res.get("history_windows_count", 0),
                "required_windows": anomaly_res.get("required_windows", 5),
                "min_required_windows": anomaly_res.get("min_required_windows", 5)
            },
            "status": summary.get("status")
        }

    return {
        "run_id": summary["run_id"],
        "top_drivers": summary["drivers"],
        "choke_points": summary["choke_points"],
        "emerging_threats": emerging_threats,
        "anomaly_detection": {
            "status": anomaly_res.get("status"),
            "model": "IsolationForest (scikit-learn)",
            "label": ANOMALY_LABEL,
            "message": anomaly_res.get("message"),
            "anomalies_detected": anomaly_res.get("anomalies_detected", 0),
            "source": anomaly_res.get("source"),
            "is_demo": anomaly_res.get("is_demo", False),
            "is_insufficient": anomaly_res.get("is_insufficient", False),
            "total_windows": anomaly_res.get("total_windows", 0),
            "history_windows_count": anomaly_res.get("history_windows_count", 0),
            "required_windows": anomaly_res.get("required_windows", 5),
            "min_required_windows": anomaly_res.get("min_required_windows", 5)
        }
    }

class InjectAnomalyRequest(BaseModel):
    agent_id: str = "AST-AD-DC-01"
    event_volume: int = 4800
    auth_failures: int = 2400
    high_severity_alerts: int = 420
    total_alerts: int = 650

@router.get("/threats/anomalies")
def get_telemetry_anomalies():
    """GET /threats/anomalies -> scikit-learn IsolationForest anomaly detection over per-agent telemetry."""
    return store.get_telemetry_anomalies()

@router.post("/threats/anomalies/inject")
def inject_telemetry_anomaly(payload: Optional[InjectAnomalyRequest] = Body(default=None)):
    """POST /threats/anomalies/inject -> Injects a telemetry spike to demonstrate IsolationForest anomaly flagging."""
    req = payload or InjectAnomalyRequest()
    conn = connections_store.get_connection("siem")
    has_siem_conn = bool(conn and conn.get("base_url") and conn.get("connected", True))
    has_real_sync = getattr(store, "has_real_siem_sync", False) or (store.current_snapshot.get("wazuh_telemetry", {}).get("source") == "Wazuh Live API")

    if not store.telemetry_history and not (has_siem_conn or has_real_sync):
        store._init_demo_telemetry_history()

    agent_id = req.agent_id
    agent_name = f"wazuh-{req.agent_id.lower()}"
    source = "Wazuh Live API" if (has_siem_conn or has_real_sync) else "demo fixture"
    is_demo = not (has_siem_conn or has_real_sync)

    if (has_siem_conn or has_real_sync) and store.telemetry_history:
        for rec in reversed(store.telemetry_history):
            if rec.get("agent_id"):
                agent_id = rec["agent_id"]
                agent_name = rec.get("agent_name", agent_id)
                break

    spike = {
        "agent_id": agent_id,
        "agent_name": agent_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_volume": req.event_volume,
        "auth_failures": req.auth_failures,
        "total_alerts": req.total_alerts,
        "high_severity_alerts": req.high_severity_alerts,
        "source": source,
        "is_demo": is_demo
    }
    store.telemetry_history.append(spike)
    res = store.get_telemetry_anomalies()
    res["injected_window"] = spike
    for sig in res.get("signals", []):
        if sig.get("agent_id") == agent_id:
            res["score_evaluation"] = sig
            break
    return res

@router.get("/risk/curve")
def get_loss_exceedance_curve():
    """GET /risk/curve -> loss exceedance points P(L > x)"""
    summary = store.get_summary()
    if store._is_empty_state(summary):
        return {"run_id": None, "curve": [], "var95": None, "var99": None, "status": summary.get("status")}
    return {
        "run_id": summary["run_id"],
        "curve": summary["curve"],
        "var95": summary["org"]["var95"],
        "var99": summary["org"]["var99"]
    }

@router.post("/simulate")
def simulate_scenario(payload: SimulateRequest):
    """POST /simulate -> {actions[], scope} -> delta EAL/VaR with bands & cost of delay"""
    res = store.whatif_sim.simulate_intervention(
        store.current_snapshot,
        payload.actions,
        seed=payload.seed
    )
    return res

@router.post("/optimize")
def optimize_investments(payload: OptimizeRequest):
    """POST /optimize -> simulated portfolio benefit and reproducible benchmarks."""
    if payload.constraints:
        raise HTTPException(status_code=422, detail="Additional optimization constraints are not yet supported")
    summary = store.get_summary()
    if store._is_empty_state(summary):
        raise HTTPException(status_code=422, detail="Cannot optimize — no risk data has been loaded yet. Upload assets and findings first.")
    base_eal = summary["org"]["eal"]
    marginal_eals = {d["id"]: d["marginal_eal"] for d in summary["drivers"]}
    # Use exact computed scenario EALs from the simulation
    scenario_eals = summary.get("scenario_eals", {})

    opt = store.get_optimizer(summary)
    benchmark_res = opt.run_benchmark(base_eal, scenario_eals, payload.budget, marginal_eals)
    plan = opt.optimize(base_eal, scenario_eals, payload.budget, marginal_eals)

    return {
        "plan": plan,
        "benchmark": benchmark_res,
        "run_id": summary["run_id"],
        "assumptions_version": summary["assumptions_version"]
    }

@router.get("/pareto")
def get_pareto_curve():
    """GET /pareto -> budget vs reduction points and knee point"""
    summary = store.get_summary()
    if store._is_empty_state(summary):
        return {"pareto_points": [], "knee_point": None, "status": summary.get("status")}
    base_eal = summary["org"]["eal"]
    marginal_eals = {d["id"]: d["marginal_eal"] for d in summary["drivers"]}
    scenario_eals = summary.get("scenario_eals", {})

    opt = store.get_optimizer(summary)
    return opt.generate_pareto_curve(base_eal, scenario_eals, marginal_eals, steps=15)

@router.get("/compliance/summary")
def get_compliance_all_summary():
    """GET /compliance/summary -> per-framework mapping coverage %, unmapped counts, compliant counts"""
    frameworks = ["sebi", "rbi", "iso", "nist", "cis", "dpdp"]
    summary = {}
    control_state = store.current_snapshot.get("control_state", [])
    for fw in frameworks:
        try:
            ev = store.framework_engine.evaluate_framework(fw, control_state, store.current_snapshot.get("compliance_assessments"), store.current_snapshot.get("reporting_exercises"))
            summary[fw] = {
                "framework_id": fw,
                "framework_name": ev["framework_name"],
                "mapping_coverage_pct": ev["mapping_coverage_pct"],
                "total_framework_requirements": ev["total_framework_requirements"],
                "mapped_requirements_count": ev["mapped_requirements_count"],
                "unmapped_requirements_count": ev["unmapped_requirements_count"],
                "overall_coverage_pct": ev["overall_coverage_pct"],
                "total_controls_mapped": ev["total_controls_mapped"],
                "compliant_controls": ev["compliant_controls"],
                "gaps_count": ev["gaps_count"]
            }
        except Exception:
            pass
    return summary

@router.get("/compliance/{framework}")
def get_compliance_eval(framework: str):
    """GET /compliance/{framework} -> coverage %, gaps, evidence links"""
    try:
        eval_res = store.framework_engine.evaluate_framework(framework, store.current_snapshot["control_state"], store.current_snapshot.get("compliance_assessments"), store.current_snapshot.get("reporting_exercises"))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return eval_res

@router.get("/compliance/{framework_id}/evidence-report")
def get_compliance_evidence_report(
    framework_id: str,
    format: Optional[str] = Query("json", description="Output format: json, csv, or html")
):
    """
    GET /compliance/{framework_id}/evidence-report -> structured audit evidence report.
    For each requirement -> CRISP coverage status -> supporting evidence (real control IDs, real finding IDs, run_id, timestamp).
    Unmapped requirements appear as 'NO EVIDENCE — unmapped'.
    Supports ?format=json, ?format=csv, or ?format=html.
    """
    try:
        report_data = EvidenceReportGenerator.build_structured_report(
            framework_id=framework_id,
            snapshot=store.current_snapshot,
            run_metadata=store.run_metadata,
            controls_catalog=store.controls_catalog
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    fmt = (format or "json").lower().strip()
    if fmt == "csv":
        csv_content = EvidenceReportGenerator.generate_csv_report(report_data)
        canonical = report_data.get("canonical_id", framework_id)
        filename = f"crisp_{canonical}_evidence_report.csv"
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    elif fmt == "html":
        html_content = EvidenceReportGenerator.generate_printable_html_report(report_data)
        return Response(content=html_content, media_type="text/html")
    else:
        return report_data

@router.get("/compliance/{framework_id}/evidence-report/csv")
def get_compliance_evidence_report_csv(framework_id: str):
    """Direct CSV download route for compliance evidence report."""
    return get_compliance_evidence_report(framework_id=framework_id, format="csv")

@router.get("/compliance/{framework_id}/evidence-report/html")
def get_compliance_evidence_report_html(framework_id: str):
    """Direct printable HTML view route for compliance evidence report."""
    return get_compliance_evidence_report(framework_id=framework_id, format="html")

@router.get("/report/{framework}")
def get_compliance_report(framework: str):
    """GET /report/{framework} -> Comprehensive printable HTML evidence report"""
    return get_compliance_evidence_report(framework_id=framework, format="html")

@router.post("/ask")
def ask_ai(payload: AskRequest):
    """POST /ask -> {question} -> answer + run_id + sources (Grounded, dynamic values)"""
    summary = store.get_summary()
    if store._is_empty_state(summary):
        return {
            "answer": f"No data has been loaded yet ({summary.get('status')}). Please upload assets and vulnerability scan results via the Data Ingestion Hub before asking analytical questions.",
            "run_id": None,
            "sources": ["CRISP System Status"]
        }
    opt = store.get_optimizer(summary)
    base_eal = summary["org"]["eal"]
    marginal_eals = {d["id"]: d["marginal_eal"] for d in summary["drivers"]}
    scenario_eals = summary.get("scenario_eals", {})
    opt_plan = opt.optimize(base_eal, scenario_eals, 10_000_000.0, marginal_eals)
    comp = store.framework_engine.evaluate_framework("sebi", store.current_snapshot["control_state"], store.current_snapshot.get("compliance_assessments"), store.current_snapshot.get("reporting_exercises"))
    
    # If the question asks about what-if or MFA, execute live simulation dynamically
    sim_res = None
    q_low = payload.question.lower()
    if "mfa" in q_low:
        sim_res = store.whatif_sim.simulate_intervention(
            store.current_snapshot,
            [{"type": "increase_control_coverage", "target_id": "CTRL-MFA-01", "coverage_pct": 100.0}],
            seed=settings.DEFAULT_SEED
        )

    res = store.ai.ask(payload.question, summary, opt_plan, comp, simulation_result=sim_res)
    return res

@router.post("/demo/inject-event")
def inject_demo_event(payload: InjectEventRequest):
    """POST /demo/inject-event -> replay a KEV/exploit event (live demo trigger)"""
    return store.inject_cve_event(payload.cve_id, payload.asset_id, payload.severity, payload.epss)

@router.get("/health/data-quality")
def get_data_quality():
    """GET /health/data-quality -> freshness, coverage, simulated-vs-real ratio"""
    assets = store.current_snapshot.get("assets", [])
    real_assets = [a for a in assets if a.get("is_real_lab_asset", False)]
    controls = store.current_snapshot.get("control_state", [])
    findings = store.current_snapshot.get("findings", [])
    wazuh_telemetry = store.current_snapshot.get("wazuh_telemetry") or {}
    wazuh_source = str(wazuh_telemetry.get("source", ""))
    wazuh_status = str(wazuh_telemetry.get("status", ""))
    is_live = bool(
        wazuh_telemetry
        and wazuh_status not in ("not_configured", "error")
        and ("live" in wazuh_source.lower())
        and (wazuh_telemetry.get("active_agents") or 0) > 0
    )
    is_simulated = bool(
        wazuh_telemetry
        and ("mock" in wazuh_source.lower() or wazuh_telemetry.get("is_simulated"))
    )
    wazuh_connected = is_live
    wazuh_live_endpoints = wazuh_telemetry.get("active_agents", 0) if is_live else 0

    active_controls = [c for c in controls if c.get("coverage_pct") is not None and c.get("evidence_ref") != "Not Connected"]

    if not assets:
        data_quality_score = 0.0
    else:
        # Asset real lab ratio (up to 0.3)
        asset_ratio = len(real_assets) / len(assets)
        # Controls coverage (up to 0.15)
        control_ratio = (len(active_controls) / max(1, len(controls))) if controls else 0.0
        # Telemetry signal boost (0.1 if live wazuh connected)
        telemetry_boost = 0.1 if wazuh_connected else 0.0
        # Base enterprise dataset readiness: 0.45
        data_quality_score = round(min(1.0, 0.45 + (asset_ratio * 0.3) + (control_ratio * 0.15) + telemetry_boost), 2)

    return {
        "status": "HEALTHY",
        "data_quality_score": data_quality_score,
        "assets_total": len(assets),
        "assets_real_lab": len(real_assets),
        "assets_simulated": len(assets) - len(real_assets),
        "findings_total": len(findings),
        "controls_telemetry_sources": {
            "wazuh_live_endpoints": wazuh_live_endpoints,
            "wazuh_connected": wazuh_connected,
            "wazuh_simulated": is_simulated,
            "openvas_findings_loaded": len(findings),
            "controls_configured": len(active_controls)
        },
        "real_vs_simulated_ratio": {
            "real_percentage": round((len(real_assets) / max(1, len(assets))) * 100, 1) if assets else 0.0,
            "simulated_percentage": round(100 - (len(real_assets) / max(1, len(assets))) * 100, 1) if assets else 0.0
        },
        "feed_freshness": {
            "cisa_kev_sync": "Live Sync Supported",
            "first_epss_sync": "Live FIRST API",
            "openvas_feed": "GMP Standard Parser Ready"
        }
    }

@router.get("/sensitivity/tornado")
def get_tornado_sensitivity():
    """GET /sensitivity/tornado -> Tornado sensitivity chart points"""
    summary = store.get_summary()
    if store._is_empty_state(summary) or not summary.get("org") or summary["org"].get("eal") is None:
        return []
    try:
        return store.sensitivity.compute_tornado(store.current_snapshot, summary["org"]["eal"])
    except Exception as e:
        logger.error(f"Error computing tornado sensitivity: {e}", exc_info=True)
        return []

@router.get("/sensitivity/convergence")
def get_monte_carlo_convergence():
    """GET /sensitivity/convergence -> EAL stabilization over 500..10000 trials"""
    return store.sensitivity.check_convergence(store.current_snapshot)

# --- Dynamic Telemetry Ingestion Endpoints ---

@router.get("/snapshot")
@router.get("/data/snapshot")
def get_active_snapshot():
    """Returns the active editable snapshot data (assets, services, findings, controls)."""
    store.dedupe_control_state()
    return {
        "assets": store.current_snapshot.get("assets", []),
        "services": store.current_snapshot.get("services", []),
        "findings": store.current_snapshot.get("findings", []),
        "control_state": store.current_snapshot.get("control_state", []),
        "controls_catalog": store.controls_catalog,
        "wazuh_telemetry": store.current_snapshot.get("wazuh_telemetry", {}),
        "cve_intel": store.current_snapshot.get("cve_intel", {})
    }


@router.post("/data/seed")
@router.post("/demo/load")
def load_demo_seed_data():
    """Loads seed demo data snapshot (assets, findings, and controls) for testing and evaluation."""
    store.load_seed()
    return {
        "status": "LOADED",
        "assets_count": len(store.current_snapshot.get("assets", [])),
        "findings_count": len(store.current_snapshot.get("findings", [])),
        "controls_count": len(store.current_snapshot.get("control_state", [])),
        "new_eal": store.cached_summary["org"]["eal"] if store.cached_summary and "org" in store.cached_summary else None
    }

@router.post("/controls/update")
def update_control_coverage(payload: UpdateControlRequest):
    """Updates the coverage % of any control dynamically and recomputes exposure."""
    result = update_controls_coverage(UpdateControlsRequest(controls=[payload]))
    return {**result, "control_id": payload.control_id, "new_coverage": payload.coverage_pct}


@router.post("/controls/bulk-update")
def update_controls_coverage(payload: UpdateControlsRequest):
    ids = [c.control_id for c in payload.controls]
    known = {c["id"] for c in store.controls_catalog}
    if len(ids) != len(set(ids)) or any(cid not in known for cid in ids):
        raise HTTPException(status_code=422, detail="Provide unique, recognized control IDs")
    original = store.current_snapshot
    store.current_snapshot = copy.deepcopy(original)
    try:
        for control in payload.controls:
            apply_control_coverage(control)
        summary = store.get_summary(force_refresh=True)
    except Exception:
        store.current_snapshot = original
        store.cached_summary = None
        raise
    return {"status": "UPDATED", "updated_count": len(ids), "new_eal": summary["org"]["eal"]}


def apply_control_coverage(payload: UpdateControlRequest):
    found = False
    now_iso = datetime.now(timezone.utc).isoformat()
    for cs in store.current_snapshot.get("control_state", []):
        if cs["control_id"] == payload.control_id:
            cs["coverage_pct"] = max(0.0, min(100.0, payload.coverage_pct))
            # If evidence was Not Connected or already User Assumption, mark as explicit user assumption
            if cs.get("evidence_ref") == "Not Connected" or not cs.get("evidence_ref") or "User Assumption" in str(cs.get("evidence_ref", "")):
                cs["evidence_ref"] = "User Assumption (unmeasured)"
                cs["is_user_assumed"] = True
                cs["is_simulated"] = False
            else:
                cs["is_user_assumed"] = True
            cs["last_checked"] = now_iso
            found = True
            break
    if not found:
        scope = "Privileged Accounts" if "MFA" in payload.control_id else ("All Endpoints" if "EDR" in payload.control_id else "Configured in UI")
        store.current_snapshot.setdefault("control_state", []).append({
            "control_id": payload.control_id,
            "asset_scope": scope,
            "coverage_pct": payload.coverage_pct,
            "evidence_ref": "User Assumption (unmeasured)",
            "last_checked": now_iso,
            "is_user_assumed": True,
            "is_simulated": False
        })

@router.post("/ingest/openvas")
async def ingest_openvas_scan(file: UploadFile = File(...)):
    """
    Parses uploaded OpenVAS report (XML, CSV, or JSON format), extracts real findings,
    enriches them with threat intel, and updates the active snapshot.
    Delegates parsing to OpenVASConnector.
    Never invents business metrics — discovered hosts are created with null business context.
    """
    content = await file.read()
    filename = file.filename or "report.xml"

    connector = OpenVASConnector()
    try:
        result = connector.parse(content, filename, finding_id_offset=len(store.current_snapshot["findings"]))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse OpenVAS scan file: {str(e)}")

    store.current_snapshot["assessment_state"] = {"status": "completed", "completed_at": datetime.now(timezone.utc).isoformat()}
    new_findings = result["findings"]
    skipped = result["skipped"]
    skip_reasons = result["skip_reasons"]

    if new_findings:
        # Register any discovered hosts in assets without inventing business context
        existing_assets = {a.get("id"): a for a in store.current_snapshot.get("assets", [])}
        for f in new_findings:
            aid = f.get("asset_id")
            if aid and aid not in existing_assets:
                new_asset = {
                    "id": aid,
                    "name": aid,
                    "type": "Discovered Host",
                    "owner": None,
                    "business_service_id": None,
                    "environment": None,
                    "internet_facing": None,
                    "data_classification": None,
                    "records_count": None,
                    "revenue_per_hour": None,
                    "criticality_1_5": None,
                    "is_real_lab_asset": True,
                    "has_business_context": False
                }
                store.current_snapshot.setdefault("assets", []).append(new_asset)
                existing_assets[aid] = new_asset

        store.merge_findings(new_findings)
        store.enrich_findings_intel(new_findings)
        store.get_summary(force_refresh=True)

    return {
        "status": "INGESTED",
        "parsed": len(new_findings),
        "skipped": skipped,
        "skip_reasons": skip_reasons,
        "total_active_findings": len(store.current_snapshot["findings"]),
        "total_active_assets": len(store.current_snapshot["assets"]),
        "new_eal": store.cached_summary["org"]["eal"] if store.cached_summary else None
    }

@router.post("/ingest/scan")
async def ingest_unified_scan(file: UploadFile = File(...)):
    """
    Unified scan ingestion endpoint supporting multiple scanner formats:
    - OpenVAS (XML with <report> root, CSV, JSON)
    - Nessus (XML with <NessusClientData_v2> root)
    Auto-detects format from file content. Returns 400 for unknown formats.
    """
    content = await file.read()
    filename = file.filename or "scan.xml"

    scan_format = detect_scan_format(content, filename)
    if scan_format == "unknown":
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported scan format. CRISP currently supports OpenVAS XML/CSV/JSON "
                "(with <report> root for XML) and Nessus XML (.nessus / <NessusClientData_v2>). "
                "Please export your scan in one of these supported formats."
            )
        )

    offset = len(store.current_snapshot["findings"])
    if scan_format == "openvas_xml":
        connector = OpenVASConnector()
        try:
            result = connector.parse(content, filename, finding_id_offset=offset)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse OpenVAS scan: {str(e)}")
    elif scan_format == "nessus_xml":
        connector = NessusConnector()
        try:
            result = connector.parse(content, finding_id_offset=offset)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse Nessus scan: {str(e)}")
    elif scan_format == "defender_edr":
        connector = DefenderEDRConnector()
        try:
            result = connector.parse(content, filename=filename, finding_id_offset=offset)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse Microsoft Defender EDR export: {str(e)}")
    else:
        raise HTTPException(status_code=400, detail=f"Unhandled scan format: {scan_format}")

    store.current_snapshot["assessment_state"] = {"status": "completed", "completed_at": datetime.now(timezone.utc).isoformat()}
    new_findings = result["findings"]
    skipped = result["skipped"]
    skip_reasons = result["skip_reasons"]

    if new_findings:
        # Register any discovered hosts in assets without inventing business context
        existing_assets = {a.get("id"): a for a in store.current_snapshot.get("assets", [])}
        for f in new_findings:
            aid = f.get("asset_id")
            if aid and aid not in existing_assets:
                new_asset = {
                    "id": aid,
                    "name": aid,
                    "type": "Discovered Host",
                    "owner": None,
                    "business_service_id": None,
                    "environment": None,
                    "internet_facing": None,
                    "data_classification": None,
                    "records_count": None,
                    "revenue_per_hour": None,
                    "criticality_1_5": None,
                    "is_real_lab_asset": True,
                    "has_business_context": False
                }
                store.current_snapshot.setdefault("assets", []).append(new_asset)
                existing_assets[aid] = new_asset

        store.merge_findings(new_findings)
        store.enrich_findings_intel(new_findings)
        store.get_summary(force_refresh=True)

    return {
        "status": "INGESTED",
        "format": scan_format,
        "detected_format": scan_format,
        "parsed": len(new_findings),
        "skipped": skipped,
        "skip_reasons": skip_reasons,
        "total_active_findings": len(store.current_snapshot["findings"]),
        "new_eal": store.cached_summary["org"]["eal"] if store.cached_summary else None
    }


@router.post("/ingest/defender")
async def ingest_defender_edr(file: UploadFile = File(...)):
    """
    POST /api/ingest/defender
    Ingests Microsoft Defender for Endpoint Advanced Hunting exports (CSV or JSON).
    Deterministic parsing of endpoint detections, severity mapping, and MITRE ATT&CK techniques.
    """
    content = await file.read()
    filename = file.filename or "defender.csv"
    offset = len(store.current_snapshot["findings"])
    connector = DefenderEDRConnector()
    try:
        result = connector.parse(content, filename=filename, finding_id_offset=offset)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse Microsoft Defender EDR export: {str(e)}")

    store.current_snapshot["assessment_state"] = {"status": "completed", "completed_at": datetime.now(timezone.utc).isoformat()}
    new_findings = result["findings"]
    skipped = result["skipped"]
    skip_reasons = result["skip_reasons"]

    if new_findings:
        existing_assets = {a.get("id"): a for a in store.current_snapshot.get("assets", [])}
        for f in new_findings:
            aid = f.get("asset_id")
            if aid and aid not in existing_assets:
                new_asset = {
                    "id": aid,
                    "name": aid,
                    "type": "Endpoint / Workstation",
                    "owner": None,
                    "business_service_id": None,
                    "environment": None,
                    "internet_facing": None,
                    "data_classification": None,
                    "records_count": None,
                    "revenue_per_hour": None,
                    "criticality_1_5": None,
                    "is_real_lab_asset": True,
                    "has_business_context": False
                }
                store.current_snapshot.setdefault("assets", []).append(new_asset)
                existing_assets[aid] = new_asset

        store.merge_findings(new_findings)
        store.enrich_findings_intel(new_findings)
        store.get_summary(force_refresh=True)

    return {
        "status": "INGESTED",
        "format": "defender_edr",
        "parsed": len(new_findings),
        "skipped": skipped,
        "skip_reasons": skip_reasons,
        "total_active_findings": len(store.current_snapshot["findings"]),
        "new_eal": store.cached_summary["org"]["eal"] if store.cached_summary else None
    }


@router.post("/ingest/wazuh-sync")
def sync_wazuh_telemetry(simulate: Optional[bool] = False):
    """
    Syncs live EDR and SIEM telemetry from Wazuh REST API.
    Records sync outcome to backend/data/sync_state.json.
    Diffs against snapshot state and recomputes FAIR risk only if data changed.
    """
    conn = connections_store.get_connection("siem")
    is_configured = bool(conn and conn.get("base_url") and conn.get("connected", True))
    now_iso = datetime.now(timezone.utc).isoformat()

    if simulate:
        source_label = "Wazuh Telemetry Mock"
        is_sim = True
        agent_data = {
            "total_agents": 6,
            "active_agents": 6,
            "disconnected_agents": 0,
            "agent_coverage_pct": 100.0,
            "agent_names": ["mock-agent-01", "mock-agent-02", "mock-agent-03", "mock-agent-04", "mock-agent-05", "mock-agent-06"]
        }
        alert_data = {
            "recent_alerts_24h": 42,
            "high_severity_alerts_24h": 3,
            "auth_failures_24h": 12
        }
    elif not is_configured:
        # When no SIEM connection is configured, do NOT silently inject mock counts.
        # Record sync status "not_configured" with zero counts.
        sync_record = sync_state_manager.record_sync(
            job_name="wazuh",
            source="none",
            counts={
                "total_agents": 0,
                "active_agents": 0,
                "assets": 0,
                "findings": 0,
                "alerts_24h": 0
            },
            status="not_configured",
            message="No SIEM/Wazuh connection configured. Pass ?simulate=true to generate mock telemetry."
        )
        store.current_snapshot["wazuh_telemetry"] = {
            "total_agents": None,
            "active_agents": None,
            "disconnected_agents": None,
            "agent_coverage_pct": None,
            "recent_alerts_24h": None,
            "high_severity_alerts_24h": None,
            "auth_failures_24h": None,
            "source": "none",
            "status": "not_configured",
            "last_sync": None
        }
        target_ctrls = [
            ("CTRL-EDR-01", "All Endpoints"),
            ("CTRL-SIEM-01", "Enterprise-wide telemetry sources")
        ]
        for cid, scope in target_ctrls:
            found = False
            for ctrl in store.current_snapshot.get("control_state", []):
                if ctrl.get("control_id") == cid:
                    ctrl["coverage_pct"] = None
                    ctrl["evidence_ref"] = "Not Connected"
                    ctrl["last_checked"] = None
                    ctrl["is_simulated"] = False
                    ctrl["is_user_assumed"] = False
                    found = True
                    break
            if not found:
                store.current_snapshot.setdefault("control_state", []).append({
                    "control_id": cid,
                    "asset_scope": scope,
                    "coverage_pct": None,
                    "evidence_ref": "Not Connected",
                    "last_checked": None,
                    "is_simulated": False,
                    "is_user_assumed": False
                })
        summary = store.check_and_recompute(trigger="sync_wazuh_not_configured")
        return {
            "status": "NOT_CONFIGURED",
            "sync_record": sync_record,
            "wazuh_telemetry": store.current_snapshot["wazuh_telemetry"],
            "edr_control": {
                "control_id": "CTRL-EDR-01",
                "coverage_pct": None,
                "evidence_ref": "Not Connected",
                "is_simulated": False
            },
            "siem_control": {
                "control_id": "CTRL-SIEM-01",
                "coverage_pct": None,
                "evidence_ref": "Not Connected",
                "is_simulated": False
            },
            "run_id": summary.get("run_id") if summary else None,
            "run_metadata": store.run_metadata,
            "new_eal": summary["org"]["eal"] if summary and summary.get("org") else None
        }
    else:
        connector = WazuhConnector(
            base_url=conn["base_url"],
            username=conn.get("username", ""),
            password=conn.get("password", "")
        )
        source_label = "Wazuh Live API"
        is_sim = False
        try:
            agent_data = connector.fetch_agent_status()
            alert_data = connector.fetch_alert_summary(hours=24)
        except Exception as e:
            sync_state_manager.record_sync(
                job_name="wazuh",
                source=source_label,
                counts={"total_agents": 0, "active_agents": 0, "assets": 0, "findings": 0},
                status="error",
                message=f"Wazuh API sync failed: {str(e)}"
            )
            store.current_snapshot["wazuh_telemetry"] = {
                "total_agents": None,
                "active_agents": None,
                "disconnected_agents": None,
                "agent_coverage_pct": None,
                "recent_alerts_24h": None,
                "high_severity_alerts_24h": None,
                "auth_failures_24h": None,
                "source": "Not Connected",
                "status": "error",
                "last_sync": now_iso
            }
            target_ids = {"CTRL-EDR-01", "CTRL-SIEM-01"}
            for ctrl in store.current_snapshot.get("control_state", []):
                if ctrl.get("control_id") in target_ids:
                    ctrl["coverage_pct"] = None
                    ctrl["evidence_ref"] = "Not Connected"
                    ctrl["last_checked"] = now_iso
                    ctrl["is_simulated"] = False
                    ctrl["is_user_assumed"] = False
            raise HTTPException(status_code=502, detail=f"Wazuh API sync failed: {str(e)}")

    total_agents = agent_data["total_agents"]
    active_agents = agent_data["active_agents"]
    agent_cov = agent_data["agent_coverage_pct"]

    # Update SIEM telemetry in snapshot
    store.current_snapshot["wazuh_telemetry"] = {
        **agent_data,
        **alert_data,
        "source": source_label,
        "status": "ok",
        "last_sync": now_iso
    }

    # Update CTRL-EDR-01 and CTRL-SIEM-01 control state
    edr_evidence_text = (
        f"{source_label} ({active_agents}/{total_agents} endpoints)"
        if not is_sim
        else f"Wazuh Telemetry Mock ({active_agents}/{total_agents} endpoints)"
    )
    siem_evidence_text = (
        f"{source_label} ({active_agents}/{total_agents} endpoints reporting)"
        if not is_sim
        else f"Wazuh Telemetry Mock ({active_agents}/{total_agents} endpoints reporting)"
    )

    controls_to_update = [
        ("CTRL-EDR-01", "All Endpoints", edr_evidence_text),
        ("CTRL-SIEM-01", "Enterprise-wide telemetry sources", siem_evidence_text)
    ]

    for cid, scope, ev_text in controls_to_update:
        found = False
        for ctrl in store.current_snapshot.get("control_state", []):
            if ctrl.get("control_id") == cid:
                ctrl["coverage_pct"] = agent_cov
                ctrl["evidence_ref"] = ev_text
                ctrl["last_checked"] = now_iso
                ctrl["is_simulated"] = is_sim
                ctrl["is_user_assumed"] = False
                found = True
                break
        if not found:
            store.current_snapshot.setdefault("control_state", []).append({
                "control_id": cid,
                "asset_scope": scope,
                "coverage_pct": agent_cov,
                "evidence_ref": ev_text,
                "last_checked": now_iso,
                "is_simulated": is_sim,
                "is_user_assumed": False
            })

    # Record sync to sync_state.json
    sync_record = sync_state_manager.record_sync(
        job_name="wazuh",
        source=source_label,
        counts={
            "total_agents": total_agents,
            "active_agents": active_agents,
            "assets": active_agents,
            "findings": 0,
            "alerts_24h": alert_data.get("recent_alerts_24h", 0)
        },
        status="ok",
        message=f"Synced {active_agents}/{total_agents} active agents"
    )

    # In real, non-simulated path only: append one real telemetry window per live agent
    if not is_sim:
        store.has_real_siem_sync = True
        store.telemetry_source = "Wazuh Live API"

        # Discard any fictional demo telemetry history when transitioning to real sync
        store.telemetry_history = [
            w for w in store.telemetry_history
            if w.get("source") == "Wazuh Live API"
        ]

        # Extract live agents from agent_data
        raw_agents = agent_data.get("agents") or []
        active_list = [a for a in raw_agents if a.get("status") == "active"]
        if not active_list and raw_agents:
            active_list = raw_agents
        elif not active_list and agent_data.get("agent_names"):
            active_list = [{"id": name, "name": name, "status": "active"} for name in agent_data["agent_names"]]
        elif not active_list and active_agents > 0:
            active_list = [{"id": f"agent-{i:03d}", "name": f"agent-{i:03d}", "status": "active"} for i in range(1, active_agents + 1)]

        vol = int(alert_data.get("recent_alerts_24h", 0) or 0)
        auth_fails = int(alert_data.get("auth_failures_24h", 0) or 0)
        high_alerts = int(alert_data.get("high_severity_alerts_24h", 0) or 0)

        for a in active_list:
            aid = str(a.get("id") or a.get("name") or "unknown")
            aname = str(a.get("name") or a.get("id") or aid)
            store.telemetry_history.append({
                "agent_id": aid,
                "agent_name": aname,
                "timestamp": now_iso,
                "event_volume": vol,
                "auth_failures": auth_fails,
                "total_alerts": vol,
                "high_severity_alerts": high_alerts,
                "source": "Wazuh Live API",
                "is_demo": False
            })

        store.telemetry_history = store.telemetry_history[-200:]
    else:
        store.telemetry_source = "Wazuh Telemetry Mock"

    # Diff against previous state and conditionally recompute
    summary = store.check_and_recompute(trigger="sync_wazuh_telemetry")

    return {
        "status": "SYNCED",
        "sync_record": sync_record,
        "wazuh_telemetry": store.current_snapshot["wazuh_telemetry"],
        "edr_control": {
            "control_id": "CTRL-EDR-01",
            "coverage_pct": agent_cov,
            "evidence_ref": edr_evidence_text,
            "is_simulated": is_sim
        },
        "siem_control": {
            "control_id": "CTRL-SIEM-01",
            "coverage_pct": agent_cov,
            "evidence_ref": siem_evidence_text,
            "is_simulated": is_sim
        },
        "run_id": summary.get("run_id") if summary else None,
        "run_metadata": store.run_metadata,
        "new_eal": summary["org"]["eal"] if summary and summary.get("org") else None
    }


@router.post("/ingest/iam-sync")
def sync_iam_telemetry(simulate: Optional[bool] = False):
    """
    Syncs privileged account MFA telemetry from Keycloak Admin REST API.
    Uses saved connection from ConnectionsStore if available, otherwise default settings.
    Updates CTRL-MFA-01 in control_state.
    Records sync outcome to backend/data/sync_state.json.
    Diffs against snapshot state and recomputes FAIR risk only if data changed.
    """
    conn = connections_store.get_connection("iam")
    is_configured = bool(conn and conn.get("base_url") and conn.get("connected", True))
    now_iso = datetime.now(timezone.utc).isoformat()

    if simulate:
        is_simulated = True
        evidence_ref = f"IAM Telemetry Mock (10/12 accounts)"
        mfa_data = {
            "total_privileged_accounts": 12,
            "mfa_enabled_count": 10,
            "mfa_coverage_pct": 83.3
        }
    elif not is_configured:
        sync_record = sync_state_manager.record_sync(
            job_name="iam",
            source="none",
            counts={"privileged_accounts": 0, "mfa_enabled": 0, "assets": 0, "findings": 0},
            status="not_configured",
            message="No IAM/Keycloak connection configured. Pass ?simulate=true to generate mock telemetry."
        )
        found = False
        for ctrl in store.current_snapshot.get("control_state", []):
            if ctrl.get("control_id") == "CTRL-MFA-01":
                ctrl["coverage_pct"] = None
                ctrl["evidence_ref"] = "Not Connected"
                ctrl["last_checked"] = None
                ctrl["is_simulated"] = False
                ctrl["is_user_assumed"] = False
                found = True
                break
        if not found:
            store.current_snapshot.setdefault("control_state", []).append({
                "control_id": "CTRL-MFA-01",
                "asset_scope": "Privileged Accounts",
                "coverage_pct": None,
                "evidence_ref": "Not Connected",
                "last_checked": None,
                "is_simulated": False,
                "is_user_assumed": False
            })
        return {
            "status": "NOT_CONFIGURED",
            "sync_record": sync_record,
            "iam_data": None,
            "control_state": {
                "control_id": "CTRL-MFA-01",
                "coverage_pct": None,
                "evidence_ref": "Not Connected",
                "is_simulated": False
            },
            "run_id": None,
            "run_metadata": store.run_metadata,
            "new_eal": None
        }
    else:
        connector = KeycloakConnector(
            base_url=conn["base_url"],
            username=conn.get("username", ""),
            password=conn.get("password", "")
        )
        try:
            mfa_data = connector.fetch_mfa_coverage()
            is_simulated = False
            total_priv = mfa_data.get("total_privileged_accounts", 0)
            mfa_cnt = mfa_data.get("mfa_enabled_count", 0)
            evidence_ref = f"Keycloak Live ({mfa_cnt}/{total_priv} accounts)"
        except Exception as e:
            sync_state_manager.record_sync(
                job_name="iam",
                source="error",
                counts={"privileged_accounts": 0, "mfa_enabled": 0, "assets": 0, "findings": 0},
                status="error",
                message=f"Keycloak API sync failed: {str(e)}"
            )
            for ctrl in store.current_snapshot.get("control_state", []):
                if ctrl.get("control_id") == "CTRL-MFA-01":
                    ctrl["coverage_pct"] = None
                    ctrl["evidence_ref"] = "Not Connected"
                    ctrl["last_checked"] = now_iso
                    ctrl["is_simulated"] = False
            raise HTTPException(status_code=502, detail=f"Keycloak API sync failed: {str(e)}")

    cov_pct = mfa_data["mfa_coverage_pct"]

    # Update CTRL-MFA-01 control state
    found = False
    for ctrl in store.current_snapshot.get("control_state", []):
        if ctrl.get("control_id") == "CTRL-MFA-01":
            ctrl["coverage_pct"] = cov_pct
            ctrl["evidence_ref"] = evidence_ref
            ctrl["last_checked"] = now_iso
            ctrl["is_simulated"] = is_simulated
            ctrl["is_user_assumed"] = False
            found = True
            break
    if not found:
        store.current_snapshot.setdefault("control_state", []).append({
            "control_id": "CTRL-MFA-01",
            "asset_scope": "Privileged Accounts",
            "coverage_pct": cov_pct,
            "evidence_ref": evidence_ref,
            "last_checked": now_iso,
            "is_simulated": is_simulated,
            "is_user_assumed": False
        })

    # Record sync to sync_state.json
    sync_record = sync_state_manager.record_sync(
        job_name="iam",
        source=evidence_ref,
        counts={
            "privileged_accounts": mfa_data.get("total_privileged_accounts", 0),
            "mfa_enabled": mfa_data.get("mfa_enabled_count", 0),
            "assets": mfa_data.get("total_privileged_accounts", 0),
            "findings": 0
        },
        status="ok",
        message=f"MFA coverage: {cov_pct}% ({mfa_data.get('mfa_enabled_count', 0)}/{mfa_data.get('total_privileged_accounts', 0)} accounts)"
    )

    # Diff against previous state and conditionally recompute
    summary = store.check_and_recompute(trigger="sync_iam_telemetry")

    return {
        "status": "SYNCED",
        "sync_record": sync_record,
        "iam_data": mfa_data,
        "control_state": {
            "control_id": "CTRL-MFA-01",
            "coverage_pct": cov_pct,
            "evidence_ref": evidence_ref,
            "is_simulated": is_simulated,
            "last_checked": now_iso
        },
        "run_id": summary.get("run_id") if summary else None,
        "run_metadata": store.run_metadata,
        "new_eal": summary["org"]["eal"] if summary and summary.get("org") else None
    }


@router.post("/ingest/cspm")
async def ingest_cspm_scan(file: UploadFile = File(...)):
    """
    Parses uploaded Prowler CSPM JSON report, extracts FAIL-status cloud findings,
    merges them into current snapshot findings, and re-runs the quantification engine.
    """
    content = await file.read()
    connector = ProwlerConnector()
    offset = len(store.current_snapshot["findings"])
    try:
        result = connector.parse(content, finding_id_offset=offset)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse Prowler CSPM report: {str(e)}")

    store.current_snapshot["assessment_state"] = {"status": "completed", "completed_at": datetime.now(timezone.utc).isoformat()}
    new_findings = result["findings"]
    skipped = result["skipped"]
    skip_reasons = result["skip_reasons"]

    if new_findings:
        store.merge_findings(new_findings)
        store.get_summary(force_refresh=True)

    return {
        "status": "INGESTED",
        "format": "prowler_json",
        "parsed": len(new_findings),
        "skipped": skipped,
        "skip_reasons": skip_reasons,
        "total_active_findings": len(store.current_snapshot["findings"]),
        "new_eal": store.cached_summary["org"]["eal"] if store.cached_summary else None
    }


# ============================================================
# VENDOR ONBOARDING WIZARD ENDPOINTS
# ============================================================

@router.post("/vendors/inspect")
async def inspect_vendor_file(file: UploadFile = File(...)):
    """
    Inspects an uploaded sample file and detects its structure, record path,
    and available fields without parsing into findings.
    """
    content = await file.read()
    filename = file.filename or ""
    ext = filename.split(".")[-1] if "." in filename else ""
    res = detect_structure(content, ext)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
    return res


@router.post("/vendors/preview")
async def preview_vendor_mapping(
    file: UploadFile = File(...),
    vendor_name: Optional[str] = Form("Preview Vendor"),
    format: str = Form(...),
    record_path: Optional[str] = Form(""),
    field_mapping: str = Form(...)
):
    """
    Runs GenericVendorConnector with a proposed, unsaved field mapping
    and returns extracted sample findings so admin can visually verify before saving.
    """
    try:
        mapping_dict = json.loads(field_mapping) if isinstance(field_mapping, str) else field_mapping
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON in field_mapping: {str(e)}")

    if not isinstance(mapping_dict, dict):
        raise HTTPException(status_code=400, detail="field_mapping must be a JSON dictionary")

    # Validate minimal mapping
    asset_id_path = mapping_dict.get("asset_id")
    severity_path = mapping_dict.get("severity")
    cve_id_path = mapping_dict.get("cve_id")
    issue_type_path = mapping_dict.get("issue_type")

    missing = []
    if not asset_id_path or not str(asset_id_path).strip():
        missing.append("asset_id")
    if not severity_path or not str(severity_path).strip():
        missing.append("severity")
    if (not cve_id_path or not str(cve_id_path).strip()) and (not issue_type_path or not str(issue_type_path).strip()):
        missing.append("at least one of cve_id or issue_type")

    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Proposed mapping incomplete. Missing required fields: {', '.join(missing)}."
        )

    temp_config = {
        "vendor_name": (vendor_name or "Preview Vendor").strip(),
        "vendor_slug": "preview_sample",
        "format": format.lower().strip(),
        "record_path": (record_path or "").strip(),
        "field_mapping": mapping_dict
    }

    content = await file.read()
    connector = GenericVendorConnector(temp_config)
    result = connector.parse(content)

    return {
        "status": "PREVIEW_OK",
        "total_extracted": len(result["findings"]),
        "total_skipped": result["skipped"],
        "skip_reasons": result["skip_reasons"][:10],
        "sample_findings": result["findings"][:10],
        "findings": result["findings"]
    }


@router.post("/vendors/save")
def save_vendor_config(payload: VendorSaveRequest):
    """
    Validates field mapping minimums and saves new vendor configuration to disk.
    """
    if not payload.vendor_name or not payload.vendor_name.strip():
        raise HTTPException(status_code=400, detail="vendor_name is required")

    mapping = payload.field_mapping or {}
    asset_id_path = mapping.get("asset_id")
    severity_path = mapping.get("severity")
    cve_id_path = mapping.get("cve_id")
    issue_type_path = mapping.get("issue_type")

    missing = []
    if not asset_id_path or not str(asset_id_path).strip():
        missing.append("asset_id")
    if not severity_path or not str(severity_path).strip():
        missing.append("severity")
    if (not cve_id_path or not str(cve_id_path).strip()) and (not issue_type_path or not str(issue_type_path).strip()):
        missing.append("at least one of cve_id or issue_type")

    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot save vendor. Required fields missing: {', '.join(missing)}."
        )

    # Generate slug from vendor name
    vendor_slug = re.sub(r"[^a-z0-9]+", "_", payload.vendor_name.lower()).strip("_")
    if not vendor_slug:
        vendor_slug = "custom_vendor"

    config_data = {
        "vendor_name": payload.vendor_name.strip(),
        "vendor_slug": vendor_slug,
        "format": payload.format.lower().strip(),
        "record_path": (payload.record_path or "").strip(),
        "field_mapping": {
            "asset_id": asset_id_path,
            "cve_id": cve_id_path,
            "cvss": mapping.get("cvss"),
            "severity": severity_path,
            "port": mapping.get("port"),
            "issue_type": issue_type_path
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sample_file_used": payload.sample_file_used or "unknown"
    }

    if tenant_active():
        configs = read_document("vendor_mappings", {})
        configs[vendor_slug] = config_data
        write_document("vendor_mappings", configs)
        return {"status": "SAVED", "config": config_data}

    mappings_dir = DATA_DIR / "vendor_mappings"
    mappings_dir.mkdir(parents=True, exist_ok=True)
    target_file = mappings_dir / f"{vendor_slug}.json"

    with open(target_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    return {"status": "SAVED", "config": config_data}


@router.get("/vendors/list")
def list_vendor_configs():
    """Returns all currently saved vendor configs."""
    if tenant_active():
        return {"vendors": list(read_document("vendor_mappings", {}).values())}
    mappings_dir = DATA_DIR / "vendor_mappings"
    if not mappings_dir.exists():
        return {"vendors": []}

    configs = []
    for f in mappings_dir.glob("*.json"):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                cfg = json.load(fp)
                configs.append(cfg)
        except Exception as e:
            logger.warning(f"Error reading vendor config {f}: {e}")

    # Sort alphabetically by vendor name
    configs.sort(key=lambda c: c.get("vendor_name", "").lower())
    return {"vendors": configs}


@router.post("/ingest/vendor/{vendor_slug}")
async def ingest_custom_vendor_scan(vendor_slug: str, file: UploadFile = File(...)):
    """
    Ingests report for a configured vendor using its saved mapping config.
    """
    if len(store.current_snapshot.get("assets", [])) == 0:
        raise HTTPException(
            status_code=400,
            detail="Please upload your asset inventory first — findings need to be linked to assets to calculate financial risk."
        )

    if not re.fullmatch(r"[a-z0-9_]+", vendor_slug):
        raise HTTPException(status_code=422, detail="Invalid vendor identifier")
    if tenant_active():
        config = read_document("vendor_mappings", {}).get(vendor_slug)
    else:
        config_file = DATA_DIR / "vendor_mappings" / f"{vendor_slug}.json"
        config = json.loads(config_file.read_text(encoding="utf-8")) if config_file.exists() else None
    if not config:
        raise HTTPException(status_code=404, detail="Vendor mapping not found in this organization")

    content = await file.read()
    connector = GenericVendorConnector(config)
    offset = len(store.current_snapshot["findings"])

    try:
        result = connector.parse(content, finding_id_offset=offset)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse {config.get('vendor_name')} report: {str(e)}")

    store.current_snapshot["assessment_state"] = {"status": "completed", "completed_at": datetime.now(timezone.utc).isoformat()}
    new_findings = result["findings"]
    skipped = result["skipped"]
    skip_reasons = result["skip_reasons"]

    if new_findings:
        store.merge_findings(new_findings)
        store.enrich_findings_intel(new_findings)
        store.get_summary(force_refresh=True)

    return {
        "status": "INGESTED",
        "vendor": config.get("vendor_name"),
        "vendor_slug": vendor_slug,
        "parsed": len(new_findings),
        "skipped": skipped,
        "skip_reasons": skip_reasons,
        "total_active_findings": len(store.current_snapshot["findings"]),
        "new_eal": store.cached_summary["org"]["eal"] if store.cached_summary else None
    }


@router.post("/data/reset")
def reset_all_data():
    """Resets the snapshot to a completely empty state."""
    store._init_empty()
    return {"status": "RESET", "message": "All assets, findings, and telemetry cleared to initial state."}


@router.post("/ingest/assets")
async def ingest_assets_file(file: UploadFile = File(...)):
    """
    Parses uploaded Asset Inventory CSV, updating assets and business services dynamically.
    Rejects XML/scan files and CSVs missing required asset schema columns.
    Never fabricates fake business parameters.
    """
    content = await file.read()

    # Guard against accidental XML/scan file upload to asset inventory
    first_chunk = content[:300].strip()
    if first_chunk.startswith(b"<?xml") or first_chunk.startswith(b"<") or b"<report" in first_chunk:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file appears to be an XML scan report, not an Asset Inventory CSV. Please upload it via the Vulnerability Scan section."
        )

    text_content = content.decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(text_content))
    headers = [h.strip() for h in (reader.fieldnames or [])]
    headers_lower = {h.lower(): h for h in headers}

    # 1. Guard against vulnerability scan CSV exports (e.g. OpenVAS CSV, Nessus CSV)
    scan_indicators = {"cvss", "nvt name", "nvt oid", "cves", "port protocol", "solution type", "cve_id", "severity"}
    matching_scan_cols = [headers_lower[c] for c in scan_indicators if c in headers_lower]
    if len(matching_scan_cols) >= 2:
        raise HTTPException(
            status_code=400,
            detail=(
                f"This looks like a vulnerability scan export (found scan columns: {', '.join(matching_scan_cols)}), "
                "not an asset inventory — please upload vulnerability scans via the 'Upload Vulnerability Scan' button."
            )
        )

    # 2. Schema requirements from Step 1 UI:
    # "Asset ID, Name, Service, Criticality (1-5), Records, RevenuePerHour"
    asset_id_col = None
    for alias in ["asset id", "assetid", "asset_id", "id"]:
        if alias in headers_lower:
            asset_id_col = headers_lower[alias]
            break

    service_col = None
    for alias in ["service", "business_service_id", "business service", "service_id"]:
        if alias in headers_lower:
            service_col = headers_lower[alias]
            break

    crit_col = None
    for alias in ["criticality", "criticality_1_5", "criticality (1-5)"]:
        if alias in headers_lower:
            crit_col = headers_lower[alias]
            break

    exposure_col = None
    for alias in ["revenueperhour", "revenue_per_hour", "revenue exposure / hr", "revenue exposure/hr", "records", "records_count", "pii records"]:
        if alias in headers_lower:
            exposure_col = headers_lower[alias]
            break

    missing = []
    if not asset_id_col:
        missing.append("Asset ID (expected: 'Asset ID' or 'id')")
    if not service_col:
        missing.append("Service (expected: 'Service' or 'business_service_id')")
    if not crit_col:
        missing.append("Criticality (expected: 'Criticality' or 'criticality_1_5')")
    if not exposure_col:
        missing.append("RevenuePerHour or Records (expected: 'RevenuePerHour' or 'Records')")

    if missing:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Missing required asset inventory columns: {', '.join(missing)}. "
                "Please upload a CSV with columns: Asset ID, Name, Service, Criticality (1-5), Records, RevenuePerHour."
            )
        )

    new_assets = []
    try:
        for idx, row in enumerate(reader):
            a_id = (row.get(asset_id_col) or "").strip()
            if not a_id:
                continue

            name = (row.get("Name") or row.get("name") or f"Host {a_id}").strip()
            svc = (row.get(service_col) or "").strip() or None

            crit_raw = (row.get(crit_col) or "").strip() if crit_col else ""
            crit = int(crit_raw) if crit_raw.isdigit() else None

            rec_col = next((headers_lower[a] for a in ["records", "records_count", "pii records"] if a in headers_lower), None)
            rec_raw = (row.get(rec_col) or "").strip() if rec_col else ""
            records = int(rec_raw) if rec_raw.isdigit() else None

            rev_col = next((headers_lower[a] for a in ["revenueperhour", "revenue_per_hour", "revenue exposure / hr", "revenue exposure/hr"] if a in headers_lower), None)
            rev_raw = (row.get(rev_col) or "").strip() if rev_col else ""
            try:
                rev = float(rev_raw) if rev_raw else None
            except ValueError:
                rev = None

            pub_col = next((headers_lower[a] for a in ["internetfacing", "internet_facing"] if a in headers_lower), None)
            pub_raw = (row.get(pub_col) or "").strip().lower() if pub_col else ""
            pub = pub_raw in ["true", "1", "yes"] if pub_raw else None

            has_biz = bool(svc or crit is not None or records is not None or rev is not None)

            new_assets.append({
                "id": a_id,
                "name": name,
                "type": row.get("Type", "Server"),
                "owner": row.get("Owner"),
                "business_service_id": svc,
                "environment": row.get("Environment", "Production"),
                "internet_facing": pub,
                "data_classification": row.get("Classification", "Confidential"),
                "records_count": records,
                "revenue_per_hour": rev,
                "criticality_1_5": crit,
                "is_real_lab_asset": True,
                "has_business_context": has_biz
            })

        if new_assets:
            existing_map = {a["id"]: a for a in store.current_snapshot.get("assets", [])}
            for a in new_assets:
                existing_map[a["id"]] = a
            store.current_snapshot["assets"] = list(existing_map.values())

            if not store.current_snapshot.get("organization"):
                store.current_snapshot["organization"] = {
                    "name": "Live Organization",
                    "risk_appetite_var95": settings.DEFAULT_RISK_APPETITE
                }
            svc_ids = {a["business_service_id"] for a in new_assets if a["business_service_id"]}
            existing_svcs = {s["service_id"] for s in store.current_snapshot.get("services", [])}
            for sid in svc_ids:
                if sid not in existing_svcs:
                    store.current_snapshot.setdefault("services", []).append({
                        "service_id": sid,
                        "name": f"Service {sid}",
                        "criticality": 4,
                        "rto_hours": 4.0
                    })
            store.get_summary(force_refresh=True)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse Asset CSV: {str(e)}")

    return {
        "status": "ASSETS_INGESTED",
        "assets_loaded": len(new_assets),
        "total_active_assets": len(store.current_snapshot["assets"]),
        "new_eal": store.cached_summary["org"]["eal"] if store.cached_summary else None
    }


@router.post("/assets/add")
def add_single_asset(payload: AddAssetRequest):
    """
    POST /api/assets/add
    Accepts a single asset object matching the asset schema.
    Validates required fields, checks for duplicate Asset IDs, appends to snapshot,
    updates services if needed, re-runs risk summary recomputation, and returns the asset.
    """
    a_id = (payload.id or payload.asset_id or "").strip()
    if not a_id:
        raise HTTPException(status_code=400, detail="Asset ID / Hostname is required.")

    # Duplicate check: check if an asset with this ID already exists
    existing_assets = store.current_snapshot.get("assets", [])
    if any(a.get("id") == a_id for a in existing_assets):
        raise HTTPException(
            status_code=400,
            detail=f"Asset with ID '{a_id}' already exists. Please choose a unique Asset ID."
        )

    crit = payload.criticality_1_5 if payload.criticality_1_5 is not None else payload.criticality
    if crit is None or not (1 <= int(crit) <= 5):
        raise HTTPException(status_code=400, detail="Criticality is required and must be an integer between 1 and 5.")
    crit = int(crit)

    rec = payload.records_count if payload.records_count is not None else payload.records
    if rec is None:
        rec = 0
    if rec < 0:
        raise HTTPException(status_code=400, detail="PII Records count cannot be negative.")

    rev = payload.revenue_per_hour
    if rev is None:
        rev = 0.0
    if rev < 0:
        raise HTTPException(status_code=400, detail="Revenue per hour cannot be negative.")

    svc = (payload.business_service_id or payload.service or "").strip() or None
    name = (payload.name or "").strip() or f"Host {a_id}"

    new_asset = {
        "id": a_id,
        "name": name,
        "type": payload.type or "Server",
        "owner": payload.owner or "Security Operations",
        "business_service_id": svc,
        "environment": payload.environment or "Production",
        "internet_facing": bool(payload.internet_facing),
        "data_classification": payload.data_classification or "Confidential",
        "records_count": rec,
        "revenue_per_hour": rev,
        "criticality_1_5": crit,
        "is_real_lab_asset": True,
        "has_business_context": True
    }

    if not store.current_snapshot.get("organization"):
        store.current_snapshot["organization"] = {
            "name": "Live Organization",
            "risk_appetite_var95": settings.DEFAULT_RISK_APPETITE
        }

    if "assets" not in store.current_snapshot:
        store.current_snapshot["assets"] = []
    store.current_snapshot["assets"].append(new_asset)

    # Register service if not existing
    if svc:
        existing_svcs = {s.get("service_id") for s in store.current_snapshot.get("services", [])}
        if svc not in existing_svcs:
            store.current_snapshot.setdefault("services", []).append({
                "service_id": svc,
                "name": f"Service {svc}",
                "criticality": crit,
                "rto_hours": 4.0
            })

    # Re-run summary recomputation
    store.get_summary(force_refresh=True)

    return {
        "status": "ASSET_ADDED",
        "asset": new_asset,
        "total_active_assets": len(store.current_snapshot["assets"]),
        "new_eal": store.cached_summary["org"]["eal"] if store.cached_summary and "org" in store.cached_summary else None
    }


@router.put("/assets/{asset_id}")
def update_single_asset(asset_id: str, payload: UpdateAssetRequest):
    """
    PUT /api/assets/{asset_id}
    Updates an existing asset's business context, criticality, and financial exposure parameters,
    syncs associated services, and recomputes the FAIR risk summary.
    """
    aid_clean = asset_id.strip()
    if not aid_clean:
        raise HTTPException(status_code=400, detail="Asset ID is required.")

    existing_assets = store.current_snapshot.get("assets", [])
    found_idx = next(
        (i for i, a in enumerate(existing_assets) if (str(a.get("id") or "").strip() == aid_clean or str(a.get("asset_id") or "").strip() == aid_clean)),
        None
    )

    if found_idx is None:
        raise HTTPException(status_code=404, detail=f"Asset with ID '{aid_clean}' not found.")

    target_asset = dict(existing_assets[found_idx])

    # Validate criticality if supplied
    crit = payload.criticality_1_5 if payload.criticality_1_5 is not None else payload.criticality
    if crit is not None:
        if not (1 <= int(crit) <= 5):
            raise HTTPException(status_code=400, detail="Criticality must be an integer between 1 and 5.")
        target_asset["criticality_1_5"] = int(crit)

    # Validate records_count if supplied
    rec = payload.records_count if payload.records_count is not None else payload.records
    if rec is not None:
        if int(rec) < 0:
            raise HTTPException(status_code=400, detail="PII Records count cannot be negative.")
        target_asset["records_count"] = int(rec)

    # Validate revenue_per_hour if supplied
    rev = payload.revenue_per_hour
    if rev is not None:
        if float(rev) < 0:
            raise HTTPException(status_code=400, detail="Revenue per hour cannot be negative.")
        target_asset["revenue_per_hour"] = float(rev)

    if payload.name is not None:
        name_val = payload.name.strip()
        if name_val:
            target_asset["name"] = name_val

    if payload.internet_facing is not None:
        target_asset["internet_facing"] = bool(payload.internet_facing)

    if payload.type is not None:
        target_asset["type"] = payload.type

    if payload.owner is not None:
        target_asset["owner"] = payload.owner

    if payload.environment is not None:
        target_asset["environment"] = payload.environment

    if payload.data_classification is not None:
        target_asset["data_classification"] = payload.data_classification

    svc = (payload.business_service_id or payload.service or "").strip()
    if svc:
        target_asset["business_service_id"] = svc
        # Register service if not existing
        existing_svcs = {s.get("service_id") for s in store.current_snapshot.get("services", [])}
        if svc not in existing_svcs:
            store.current_snapshot.setdefault("services", []).append({
                "service_id": svc,
                "name": f"Service {svc}",
                "criticality": target_asset.get("criticality_1_5") or 4,
                "rto_hours": 4.0
            })

    # When updated with criticality or service, asset now has declared business context
    has_biz = bool(target_asset.get("business_service_id") or target_asset.get("criticality_1_5") is not None)
    target_asset["has_business_context"] = has_biz

    # Update asset in snapshot
    existing_assets[found_idx] = target_asset
    store.current_snapshot["assets"] = existing_assets

    # Force recompute FAIR risk summary
    store.get_summary(force_refresh=True)

    new_eal = None
    if store.cached_summary and isinstance(store.cached_summary.get("org"), dict):
        new_eal = store.cached_summary["org"].get("eal")

    return {
        "status": "ASSET_UPDATED",
        "asset": target_asset,
        "total_active_assets": len(store.current_snapshot["assets"]),
        "new_eal": new_eal
    }


@router.delete("/assets/{asset_id}")

def delete_single_asset(asset_id: str):
    """
    DELETE /api/assets/{asset_id}
    Removes the specified asset from the active snapshot, removes any findings
    directly tied to this asset, recomputes the FAIR risk summary, and returns the updated count and EAL.
    """
    aid_clean = asset_id.strip()
    if not aid_clean:
        raise HTTPException(status_code=400, detail="Asset ID is required.")

    existing_assets = store.current_snapshot.get("assets", [])
    found_asset = next(
        (a for a in existing_assets if (str(a.get("id") or "").strip() == aid_clean or str(a.get("asset_id") or "").strip() == aid_clean)),
        None
    )

    if not found_asset:
        raise HTTPException(status_code=404, detail=f"Asset with ID '{aid_clean}' not found.")

    # Remove the asset from snapshot
    store.current_snapshot["assets"] = [
        a for a in existing_assets
        if str(a.get("id") or "").strip() != aid_clean and str(a.get("asset_id") or "").strip() != aid_clean
    ]

    # Also remove findings associated with this asset
    existing_findings = store.current_snapshot.get("findings", [])
    store.current_snapshot["findings"] = [
        f for f in existing_findings
        if str(f.get("asset_id") or "").strip() != aid_clean
    ]

    # Clean up orphaned services if no remaining assets reference them
    remaining_service_ids = {
        str(a.get("business_service_id") or "").strip()
        for a in store.current_snapshot["assets"]
        if a.get("business_service_id")
    }
    if "services" in store.current_snapshot:
        store.current_snapshot["services"] = [
            s for s in store.current_snapshot["services"]
            if str(s.get("service_id") or "").strip() in remaining_service_ids
        ]

    # Force recompute FAIR risk summary
    store.get_summary(force_refresh=True)

    new_eal = None
    if store.cached_summary and isinstance(store.cached_summary.get("org"), dict):
        new_eal = store.cached_summary["org"].get("eal")

    return {
        "status": "ASSET_DELETED",
        "asset_id": aid_clean,
        "total_active_assets": len(store.current_snapshot["assets"]),
        "new_eal": new_eal
    }


@router.delete("/assets")
@router.post("/assets/clear")
def clear_asset_inventory():
    """
    DELETE /api/assets or POST /api/assets/clear
    Clears all active assets, associated findings, and services from the snapshot,
    re-running risk summary recomputation (returning to clean empty state).
    """
    deleted_count = len(store.current_snapshot.get("assets", []))
    store.current_snapshot["assets"] = []
    store.current_snapshot["findings"] = []
    store.current_snapshot["services"] = []
    store.cached_summary = None
    store.last_state_signature = None
    store.get_summary(force_refresh=True)

    return {
        "status": "INVENTORY_CLEARED",
        "assets_removed": deleted_count,
        "total_active_assets": 0,
        "message": "All assets cleared from inventory.",
        "new_eal": None
    }



@router.post("/ingest/sync-live-intel")
def sync_live_threat_intel():
    """Synchronizes CISA KEV catalog, FIRST EPSS, and NIST NVD API v2 for all active CVEs."""
    return store.sync_live_threat_intel()


@router.get("/threat-intel/provenance")
def get_threat_intel_provenance(cve_id: Optional[str] = None):
    """
    GET /api/threat-intel/provenance
    Surfaces per-finding / per-CVE threat intelligence provenance:
    - FIRST EPSS (score, percentile, fetch timestamp, status)
    - NIST NVD API v2 (CVSS v3.x score & vector, description, publication date, status)
    - CISA KEV Catalog (in_kev membership, active exploitation label, date added, status)
    """
    cve_intel = store.current_snapshot.get("cve_intel", {})
    if cve_id:
        cve_clean = cve_id.strip().upper()
        if cve_clean in cve_intel:
            data = cve_intel[cve_clean]
            return {
                "cve_id": cve_clean,
                "in_kev": data.get("in_kev", False),
                "exploitability_label": data.get("exploitability_label"),
                "provenance": data.get("provenance"),
                "intel": data
            }
        # If not loaded in snapshot yet, query feed directly
        enriched = store.threat_intel.enrich_cve(cve_clean, local_cache=cve_intel)
        return {
            "cve_id": cve_clean,
            "in_kev": enriched.get("in_kev", False),
            "exploitability_label": enriched.get("exploitability_label"),
            "provenance": enriched.get("provenance"),
            "intel": enriched
        }

    # Build response for all CVEs in active snapshot
    findings = store.current_snapshot.get("findings", [])
    findings_provenance = [
        {
            "finding_id": f.get("id"),
            "cve_id": f.get("cve_id"),
            "asset_id": f.get("asset_id"),
            "severity": f.get("severity"),
            "in_kev": f.get("in_kev", False),
            "exploitability_label": f.get("exploitability_label"),
            "threat_intel_provenance": f.get("threat_intel_provenance") or (cve_intel.get(f.get("cve_id", "")).get("provenance") if f.get("cve_id") in cve_intel else None)
        }
        for f in findings if f.get("cve_id")
    ]

    return {
        "total_cves": len(cve_intel),
        "total_findings_with_cve": len(findings_provenance),
        "cve_intel": cve_intel,
        "findings_provenance": findings_provenance
    }


# --- Connections Settings Endpoints ---

@router.get("/connections")
def get_connections():
    """
    GET /api/connections
    Returns the status of all saved connections (connected, base_url, username, last_tested,
    last_test_result, last_test_detail).
    Explicitly EXCLUDES any password / encrypted_password field from the response.
    """
    return connections_store.get_all_public()


@router.post("/connections/refresh")
def refresh_connections():
    """Recheck saved endpoints and synchronize telemetry; report failures per connector."""
    results = {}
    for category, sync in (("siem", sync_wazuh_telemetry), ("iam", sync_iam_telemetry)):
        configured = connections_store.get_public_connection(category)
        if not configured or not configured.get("base_url"):
            continue
        try:
            result = connections_store.test_connection(category)
        except Exception:
            result = {"success": False, "detail": "Saved credentials could not be read. Edit and save the connection again."}
        connections_store.record_connection_result(category, bool(result.get("success")), result.get("detail", ""))
        try:
            # Failed checks also clear stale coverage through the not-connected path.
            sync(simulate=False)
        except Exception as exc:
            result = {"success": False, "detail": str(getattr(exc, "detail", "Telemetry synchronization failed"))}
            connections_store.record_connection_result(category, False, result["detail"])
        results[category] = result
    return {"connections": connections_store.get_all_public(), "results": results}


@router.post("/connections/{category}/test")
def test_connection_endpoint(category: str, payload: ConnectionPayload):
    """
    POST /api/connections/{category}/test
    Attempts a real, live connection using the relevant connector without saving.
    Returns {success: bool, detail: str}.
    """
    res = connections_store.test_connection(
        category=category,
        base_url=payload.base_url,
        username=payload.username or "",
        password=payload.password or ""
    )
    return res


@router.post("/connections/{category}/save")
def save_connection_endpoint(category: str, payload: ConnectionPayload):
    """
    POST /api/connections/{category}/save
    Saves connection with encrypted credentials. Never echoes password in response.
    """
    try:
        saved = connections_store.save_connection(
            category=category,
            base_url=payload.base_url,
            username=payload.username or "",
            password=payload.password or ""
        )
        # If connection is active, trigger immediate snapshot sync
        if saved.get("connected"):
            if category.lower() in ["siem", "edr", "wazuh"]:
                try:
                    sync_wazuh_telemetry()
                except Exception as e:
                    logger.warning(f"Immediate SIEM sync warning: {e}")
            elif category.lower() in ["iam", "keycloak"]:
                try:
                    sync_iam_telemetry(simulate=False)
                except Exception as e:
                    logger.warning(f"Immediate IAM sync warning: {e}")

        return {
            "status": "SAVED",
            "connection": saved
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save connection: {str(e)}")


@router.delete("/connections/{category}")
def delete_connection_endpoint(category: str):
    """
    DELETE /api/connections/{category}
    Removes a saved connection.
    """
    removed = connections_store.remove_connection(category)
    if removed and category.lower() in ("siem", "edr", "wazuh"):
        store.has_real_siem_sync = False
        store.telemetry_source = "none"
        sync_wazuh_telemetry(simulate=False)
    return {
        "status": "REMOVED" if removed else "NOT_FOUND",
        "category": category
    }


# --- Multi-Provider LLM Configuration Endpoints ---

@router.get("/ai/config")
def get_ai_config():
    """
    GET /api/ai/config
    Returns active LLM provider, model, masked API key, and list of supported providers.
    """
    return llm_config_store.get_public_config()


@router.post("/ai/config")
def save_ai_config(payload: LLMConfigPayload):
    """
    POST /api/ai/config
    Persists updated LLM settings with Fernet-encrypted API key.
    """
    return llm_config_store.save_config(
        provider=payload.provider,
        model=payload.model,
        api_key=payload.api_key,
        base_url=payload.base_url,
        temperature=payload.temperature if payload.temperature is not None else 0.2,
        enabled=payload.enabled if payload.enabled is not None else True
    )


@router.post("/ai/test")
def test_ai_connection(payload: LLMConfigPayload):
    """
    POST /api/ai/test
    Tests connection to the specified LLM provider and measures latency.
    """
    return llm_service.test_connection(payload.model_dump())


# --- Continuous Telemetry Synchronization Endpoints ---

@router.post("/sync/all")
def trigger_sync_all():
    """
    POST /api/sync/all
    Executes a manual synchronization across all configured telemetry and intelligence sources:
    1. Wazuh EDR & SIEM
    2. Keycloak IAM
    3. CISA KEV / NVD / EPSS Threat Intel
    Records results to sync_state.json and diffs against snapshot state.
    Triggers engine recompute and mints a new run_id ONLY if data changed.
    """
    job_results = {}
    try:
        w_res = sync_wazuh_telemetry()
        job_results["wazuh"] = w_res.get("status")
    except Exception as e:
        job_results["wazuh"] = f"error: {e}"

    try:
        i_res = sync_iam_telemetry(simulate=False)
        job_results["iam"] = i_res.get("status")
    except Exception as e:
        job_results["iam"] = f"error: {e}"

    try:
        t_res = store.sync_live_threat_intel()
        job_results["threat_intel"] = t_res.get("status")
    except Exception as e:
        job_results["threat_intel"] = f"error: {e}"

    summary = store.cached_summary
    return {
        "status": "COMPLETED",
        "job_results": job_results,
        "run_id": summary.get("run_id") if summary else None,
        "run_metadata": store.run_metadata,
        "freshness": sync_state_manager.get_freshness_summary(),
        "sync_state": sync_state_manager.get_state()
    }


@router.get("/sync/state")
def get_sync_state():
    """
    GET /api/sync/state
    Returns the current persistent synchronization state and header freshness indicators.
    """
    return {
        "sync_state": sync_state_manager.get_state(),
        "freshness": sync_state_manager.get_freshness_summary(),
        "run_metadata": store.run_metadata
    }




@router.get("/risk/explanation")
def explain_risk():
    result = store.get_summary()
    return {"status":result.get("status"), "run_id":result.get("run_id"),
            "model_version":result.get("model_version"), "snapshot_hash":result.get("snapshot_hash"),
            "seed":result.get("seed"), "trials":result.get("trials"),
            "loss_components":result.get("loss_breakdown"), "excluded_assets":result.get("excluded_assets"),
            "explanation":result.get("explanation")}


@router.put("/model/assumptions")
def update_model_assumptions(payload: Dict[str, Any] = Body(...)):
    candidate = copy.deepcopy(store.current_snapshot)
    candidate["model_assumptions"] = payload
    resolved = assumptions(candidate)
    store.current_snapshot = candidate
    result = store.get_summary(force_refresh=True)
    return {"assumptions":resolved,"run_id":result.get("run_id")}


class ReviewRequest(BaseModel):
    decision: str = Field(pattern="^(compliant|partial|non_compliant|not_assessed)$")
    applicability: str = Field(default="applicable", pattern="^(applicable|not_applicable|not_reviewed)$")
    notes: str = ""


@router.put("/governance/reviews/{requirement_id}")
def record_review(requirement_id: str, payload: ReviewRequest):
    from app.compliance.framework_registry import FRAMEWORK_REQUIREMENTS
    from app.compliance.evidence import evidence_fingerprint
    known = {r["id"] for rows in FRAMEWORK_REQUIREMENTS.values() for r in rows}
    known.update(c["id"] for c in store.controls_catalog)
    if requirement_id not in known:
        raise HTTPException(status_code=404,detail="Unknown requirement/control")
    review = {**payload.model_dump(),"reviewer":(principal_context.get() or {}).get("subject","local-reviewer"),
              "reviewed_at":datetime.now(timezone.utc).isoformat()}
    requirement = next((r for rows in FRAMEWORK_REQUIREMENTS.values() for r in rows if r["id"] == requirement_id), {})
    cid = requirement.get("mapped_control_id", requirement_id)
    state = next((c for c in store.current_snapshot.get("control_state", []) if c["control_id"] == cid), {})
    review["evidence_fingerprint"] = evidence_fingerprint(state)
    store.current_snapshot.setdefault("compliance_assessments",{})[requirement_id] = review
    return review


class ExerciseRequest(BaseModel):
    id: str
    incident_at: datetime
    detected_at: datetime
    escalated_at: datetime
    reported_at: datetime
    evidence_ref: str = Field(min_length=1)


@router.post("/governance/exercises")
def record_exercise(payload: ExerciseRequest):
    from app.compliance.evidence import reporting_readiness
    item = payload.model_dump(mode="json")
    if not reporting_readiness([item])["exercises"]:
        raise HTTPException(status_code=422,detail="Exercise timestamps must be ordered, in the past and within 90 days")
    exercises = store.current_snapshot.setdefault("reporting_exercises",[])
    exercises[:] = [x for x in exercises if x["id"] != item["id"]]
    exercises.append(item)
    return reporting_readiness(exercises)


@router.get("/governance/audit")
def get_audit_events():
    if not tenant_active():
        return {"events":[]}
    rows = transaction_context.get().execute("SELECT id,subject,action,status,timestamp,before_hash,after_hash FROM audit_events WHERE tenant=? ORDER BY id DESC LIMIT 200",(principal_context.get()["tenant"],))
    return {"events":[dict(zip(("id","subject","action","status","timestamp","before_hash","after_hash"),row)) for row in rows]}
