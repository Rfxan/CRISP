import yaml
from pathlib import Path
from typing import Dict, Any
from app.core.config import DATA_DIR, settings

class AssumptionsLedger:
    _instance = None
    _data: Dict[str, Any] = {}

    def __init__(self):
        self.load()

    def load(self):
        yaml_path = DATA_DIR / "assumptions.yaml"
        if yaml_path.exists():
            with open(yaml_path, "r", encoding="utf-8") as f:
                self._data = yaml.safe_load(f)
        else:
            self._data = {
                "version": settings.ASSUMPTIONS_VERSION,
                "loss_parameters": {},
                "threat_event_frequencies": {}
            }

    @property
    def version(self) -> int:
        return self._data.get("version", settings.ASSUMPTIONS_VERSION)

    @property
    def data(self) -> Dict[str, Any]:
        return self._data

assumptions_ledger = AssumptionsLedger()
