import json
from pathlib import Path
from typing import Dict, Any, List
from app.core.config import DATA_DIR

FRAMEWORKS = {
    "iso": {
        "name": "ISO/IEC 27001:2022",
        "description": "Information Security Management System - Annex A Controls",
        "citation": "ISO/IEC 27001:2022 Information security, cybersecurity and privacy protection"
    },
    "nist": {
        "name": "NIST CSF 2.0",
        "description": "National Institute of Standards & Technology Cybersecurity Framework 2.0",
        "citation": "NIST CSWP 29 (Feb 2024)"
    },
    "cis": {
        "name": "CIS Controls v8",
        "description": "Center for Internet Security Critical Security Controls Version 8",
        "citation": "CIS Controls v8 (Center for Internet Security 2021)"
    },
    "rbi": {
        "name": "RBI Cyber Security Framework",
        "description": "Reserve Bank of India Cyber Security Framework for Banks and NBFCs",
        "citation": "RBI Circular RBI/2015-16/418 & Master Directions on IT Governance"
    },
    "sebi": {
        "name": "SEBI CSCRF",
        "description": "Cybersecurity and Cyber Resilience Framework for Regulated Entities",
        "citation": "SEBI Circular SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113 (Aug 20, 2024)"
    },
    "dpdp": {
        "name": "DPDP Act & Rules 2025",
        "description": "Digital Personal Data Protection Act 2023 & Rules 2025 Reasonable Safeguards",
        "citation": "MeitY Notification & PIB Release Nov 17, 2025"
    }
}

class ControlCatalog:
    def __init__(self):
        catalog_path = DATA_DIR / "controls_catalog.json"
        with open(catalog_path, "r", encoding="utf-8") as f:
            self.controls: List[Dict[str, Any]] = json.load(f)

    def get_all_controls(self) -> List[Dict[str, Any]]:
        return self.controls

    def get_control(self, control_id: str) -> Dict[str, Any]:
        return next((c for c in self.controls if c["id"] == control_id), None)
