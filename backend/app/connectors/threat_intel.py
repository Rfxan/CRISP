"""
CRISP Threat Intelligence Connector (Re-exporting from app.ai.threat_intel).
Maintains backward compatibility for imports from app.connectors.threat_intel.
"""

from app.ai.threat_intel import (
    ThreatIntelFeed,
    NVD_TTL_SECONDS,
    KEV_TTL_SECONDS,
    EPSS_TTL_SECONDS,
    NVD_BASE_URL,
    CISA_KEV_URL,
    FIRST_EPSS_URL,
)

__all__ = [
    "ThreatIntelFeed",
    "NVD_TTL_SECONDS",
    "KEV_TTL_SECONDS",
    "EPSS_TTL_SECONDS",
    "NVD_BASE_URL",
    "CISA_KEV_URL",
    "FIRST_EPSS_URL",
]
