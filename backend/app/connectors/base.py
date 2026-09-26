from abc import ABC, abstractmethod
from typing import Dict, Any, List

class BaseConnector(ABC):
    @abstractmethod
    def fetch(self) -> Dict[str, Any]:
        """Fetch raw telemetry/scan data from source."""
        pass

    @abstractmethod
    def normalize(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Normalize raw data into CRISP canonical model."""
        pass
