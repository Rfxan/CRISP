import json

timestamp = "2026-09-24T12:00:00Z"

services = [
    {
        "id": "SVC-PAY",
        "name": "UPI & Payment Gateway Switch",
        "revenue_per_hour": 2500000.0,
        "rto_hours": 2.0,
        "depends_on": ["SVC-CORE"]
    },
    {
        "id": "SVC-CORE",
        "name": "Core Banking System (CBS Engine)",
        "revenue_per_hour": 3800000.0,
        "rto_hours": 4.0,
        "depends_on": []
    },
    {
        "id": "SVC-NETBANK",
        "name": "Retail NetBanking & Mobile API",
        "revenue_per_hour": 1200000.0,
        "rto_hours": 4.0,
        "depends_on": ["SVC-CORE", "SVC-PAY"]
    },
    {
        "id": "SVC-LOAN",
        "name": "Instant Digital Lending Platform",
        "revenue_per_hour": 650000.0,
        "rto_hours": 8.0,
        "depends_on": ["SVC-CORE"]
    },
    {
        "id": "SVC-CRM",
        "name": "Customer Data & CRM Repository",
        "revenue_per_hour": 350000.0,
        "rto_hours": 12.0,
        "depends_on": []
    },
    {
        "id": "SVC-CORP",
        "name": "Corporate Active Directory & ERP",
        "revenue_per_hour": 150000.0,
        "rto_hours": 24.0,
        "depends_on": []
    }
]

assets = [
    {
        "id": "AST-PAY-DB-01",
        "name": "pay-db-primary (PostgreSQL Cluster)",
        "type": "Database Server",
        "owner": "Payments Infra Team",
        "business_service_id": "SVC-PAY",
        "environment": "Production",
        "internet_facing": False,
        "data_classification": "Restricted Financial PII",
        "records_count": 3200000,
        "revenue_per_hour": 2500000.0,
        "criticality_1_5": 5,
        "is_real_lab_asset": True
    },
    {
        "id": "AST-PAY-GW-01",
        "name": "pay-gateway-ingress (Nginx / API Gateway)",
        "type": "API Gateway",
        "owner": "Payments Infra Team",
        "business_service_id": "SVC-PAY",
        "environment": "DMZ",
        "internet_facing": True,
        "data_classification": "Internal",
        "records_count": 0,
        "revenue_per_hour": 2500000.0,
        "criticality_1_5": 5,
        "is_real_lab_asset": True
    },
    {
        "id": "AST-CORE-DB-01",
        "name": "cbs-db-oracle-01 (Oracle RAC)",
        "type": "Database Server",
        "owner": "Core Banking Team",
        "business_service_id": "SVC-CORE",
        "environment": "Production",
        "internet_facing": False,
        "data_classification": "Restricted Financial PII",
        "records_count": 5400000,
        "revenue_per_hour": 3800000.0,
        "criticality_1_5": 5,
        "is_real_lab_asset": False
    },
    {
        "id": "AST-NETBANK-APP-01",
        "name": "netbank-k8s-ingress (Kubernetes Ingress)",
        "type": "Load Balancer / Ingress",
        "owner": "Digital Banking Team",
        "business_service_id": "SVC-NETBANK",
        "environment": "DMZ",
        "internet_facing": True,
        "data_classification": "Internal",
        "records_count": 50000,
        "revenue_per_hour": 1200000.0,
        "criticality_1_5": 4,
        "is_real_lab_asset": True
    },
    {
        "id": "AST-AD-DC-01",
        "name": "corp-ad-dc-01 (Primary Domain Controller)",
        "type": "Directory Server",
        "owner": "Enterprise IT Team",
        "business_service_id": "SVC-CORP",
        "environment": "Internal",
        "internet_facing": False,
        "data_classification": "Confidential Credentials",
        "records_count": 4500,
        "revenue_per_hour": 150000.0,
        "criticality_1_5": 4,
        "is_real_lab_asset": True
    },
    {
        "id": "AST-CRM-APP-01",
        "name": "crm-customer360-app (Spring Boot Service)",
        "type": "Application Server",
        "owner": "CRM & Analytics",
        "business_service_id": "SVC-CRM",
        "environment": "Production",
        "internet_facing": False,
        "data_classification": "Confidential Customer PII",
        "records_count": 2800000,
        "revenue_per_hour": 350000.0,
        "criticality_1_5": 3,
        "is_real_lab_asset": True
    }
]

for i in range(7, 121):
    svc_id = ["SVC-PAY", "SVC-CORE", "SVC-NETBANK", "SVC-LOAN", "SVC-CRM", "SVC-CORP"][i % 6]
    is_pub = (i % 5 == 0)
    crit = 4 if i < 20 else (3 if i < 60 else (2 if i < 100 else 1))
    assets.append({
        "id": f"AST-NODE-{i:03d}",
        "name": f"node-{svc_id.lower().replace('svc-', '')}-{i:03d}",
        "type": "Compute Instance" if i % 2 == 0 else "Microservice Container",
        "owner": "Cloud Ops Team",
        "business_service_id": svc_id,
        "environment": "Production" if i % 3 != 0 else "Staging",
        "internet_facing": is_pub,
        "data_classification": "Internal" if not is_pub else "Public",
        "records_count": 5000 * (i % 10),
        "revenue_per_hour": round(15000.0 + (i * 250.0), 2),
        "criticality_1_5": crit,
        "is_real_lab_asset": False
    })

cve_intel = {
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI RCE vulnerability (Log4Shell)",
        "epss": 0.974,
        "epss_percentile": 0.999,
        "in_kev": True,
        "exploit_public": True,
        "published": "2021-12-10"
    },
    "CVE-2022-22965": {
        "cve_id": "CVE-2022-22965",
        "description": "Spring Framework RCE via Data Binding (Spring4Shell)",
        "epss": 0.885,
        "epss_percentile": 0.985,
        "in_kev": True,
        "exploit_public": True,
        "published": "2022-04-01"
    },
    "CVE-2021-34527": {
        "cve_id": "CVE-2021-34527",
        "description": "Windows Print Spooler Remote Code Execution (PrintNightmare)",
        "epss": 0.824,
        "epss_percentile": 0.971,
        "in_kev": True,
        "exploit_public": True,
        "published": "2021-07-02"
    },
    "CVE-2024-3400": {
        "cve_id": "CVE-2024-3400",
        "description": "Palo Alto Networks PAN-OS GlobalProtect Command Injection",
        "epss": 0.925,
        "epss_percentile": 0.992,
        "in_kev": True,
        "exploit_public": True,
        "published": "2024-04-12"
    },
    "CVE-2023-4966": {
        "cve_id": "CVE-2023-4966",
        "description": "Citrix NetScaler ADC/Gateway Sensitive Information Disclosure (Citrix Bleed)",
        "epss": 0.941,
        "epss_percentile": 0.995,
        "in_kev": True,
        "exploit_public": True,
        "published": "2023-10-10"
    },
    "CVE-2024-21413": {
        "cve_id": "CVE-2024-21413",
        "description": "Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink)",
        "epss": 0.742,
        "epss_percentile": 0.952,
        "in_kev": True,
        "exploit_public": True,
        "published": "2024-02-13"
    },
    "CVE-2023-38606": {
        "cve_id": "CVE-2023-38606",
        "description": "Linux Kernel local privilege escalation",
        "epss": 0.354,
        "epss_percentile": 0.820,
        "in_kev": False,
        "exploit_public": True,
        "published": "2023-08-20"
    },
    "CVE-2023-48795": {
        "cve_id": "CVE-2023-48795",
        "description": "SSH Terrapin prefix truncation attack",
        "epss": 0.220,
        "epss_percentile": 0.710,
        "in_kev": False,
        "exploit_public": False,
        "published": "2023-12-18"
    },
    "CVE-2024-6387": {
        "cve_id": "CVE-2024-6387",
        "description": "OpenSSH regreSSHion signal handler race condition RCE",
        "epss": 0.650,
        "epss_percentile": 0.910,
        "in_kev": True,
        "exploit_public": True,
        "published": "2024-07-01"
    }
}

findings = [
    {
        "id": "FND-001",
        "asset_id": "AST-PAY-DB-01",
        "cve_id": "CVE-2021-44228",
        "cvss": 10.0,
        "severity": "Critical",
        "port": 8080,
        "first_seen": "2026-09-10T08:00:00Z",
        "last_seen": timestamp,
        "source": "OpenVAS Scanner"
    },
    {
        "id": "FND-002",
        "asset_id": "AST-PAY-GW-01",
        "cve_id": "CVE-2024-3400",
        "cvss": 10.0,
        "severity": "Critical",
        "port": 443,
        "first_seen": "2026-09-12T14:30:00Z",
        "last_seen": timestamp,
        "source": "OpenVAS Scanner"
    },
    {
        "id": "FND-003",
        "asset_id": "AST-NETBANK-APP-01",
        "cve_id": "CVE-2023-4966",
        "cvss": 9.4,
        "severity": "Critical",
        "port": 443,
        "first_seen": "2026-09-15T09:15:00Z",
        "last_seen": timestamp,
        "source": "OpenVAS Scanner"
    },
    {
        "id": "FND-004",
        "asset_id": "AST-AD-DC-01",
        "cve_id": "CVE-2021-34527",
        "cvss": 8.8,
        "severity": "High",
        "port": 445,
        "first_seen": "2026-09-11T11:00:00Z",
        "last_seen": timestamp,
        "source": "OpenVAS Scanner"
    },
    {
        "id": "FND-005",
        "asset_id": "AST-CRM-APP-01",
        "cve_id": "CVE-2022-22965",
        "cvss": 9.8,
        "severity": "Critical",
        "port": 8080,
        "first_seen": "2026-09-14T16:20:00Z",
        "last_seen": timestamp,
        "source": "OpenVAS Scanner"
    },
    {
        "id": "FND-006",
        "asset_id": "AST-CORE-DB-01",
        "cve_id": "CVE-2023-38606",
        "cvss": 7.8,
        "severity": "High",
        "port": 1521,
        "first_seen": "2026-09-08T10:00:00Z",
        "last_seen": timestamp,
        "source": "OpenVAS Scanner"
    },
    {
        "id": "FND-007",
        "asset_id": "AST-NODE-007",
        "cve_id": "CVE-2024-6387",
        "cvss": 8.1,
        "severity": "High",
        "port": 22,
        "first_seen": "2026-09-18T05:00:00Z",
        "last_seen": timestamp,
        "source": "OpenVAS Scanner"
    },
    {
        "id": "FND-008",
        "asset_id": "AST-NODE-012",
        "cve_id": "CVE-2023-48795",
        "cvss": 5.9,
        "severity": "Medium",
        "port": 22,
        "first_seen": "2026-09-16T12:00:00Z",
        "last_seen": timestamp,
        "source": "OpenVAS Scanner"
    }
]

wazuh_telemetry = {
    "total_agents": 120,
    "active_agents": 114,
    "disconnected_agents": 6,
    "last_sync": timestamp,
    "agent_coverage_pct": 95.0,
    "recent_alerts_24h": 1420,
    "high_severity_alerts_24h": 38,
    "auth_failures_24h": 512,
    "fim_modifications_detected": 14,
    "rootcheck_anomalies": 2
}

control_state = [
    {
        "control_id": "CTRL-MFA-01",
        "asset_scope": "All Privileged Admin & DB Accounts",
        "coverage_pct": 62.0,
        "evidence_ref": "IAM Telemetry Mock / Azure AD Log Export",
        "last_checked": timestamp,
        "is_simulated": True
    },
    {
        "control_id": "CTRL-EDR-01",
        "asset_scope": "All Corporate & Cloud Compute Nodes",
        "coverage_pct": 95.0,
        "evidence_ref": "Wazuh Active Agent Telemetry (114/120 endpoints)",
        "last_checked": timestamp,
        "is_simulated": False
    },
    {
        "control_id": "CTRL-PATCH-01",
        "asset_scope": "Internet-Facing & Tier-1 Core Servers",
        "coverage_pct": 58.0,
        "evidence_ref": "OpenVAS Vulnerability Scan SLA Engine",
        "last_checked": timestamp,
        "is_simulated": False
    },
    {
        "control_id": "CTRL-ENC-01",
        "asset_scope": "Primary Database Repositories",
        "coverage_pct": 70.0,
        "evidence_ref": "Database Schema & Storage Audit Logs",
        "last_checked": timestamp,
        "is_simulated": True
    },
    {
        "control_id": "CTRL-WAF-01",
        "asset_scope": "DMZ Edge & Customer Ingress Ports",
        "coverage_pct": 85.0,
        "evidence_ref": "Cloudflare / WAF Policy Logs",
        "last_checked": timestamp,
        "is_simulated": False
    },
    {
        "control_id": "CTRL-SEG-01",
        "asset_scope": "Payment Switch & Core Banking VLANs",
        "coverage_pct": 60.0,
        "evidence_ref": "Software Defined Perimeter / Firewall rule table",
        "last_checked": timestamp,
        "is_simulated": True
    },
    {
        "control_id": "CTRL-BKP-01",
        "asset_scope": "Critical CBS & Payment Databases",
        "coverage_pct": 50.0,
        "evidence_ref": "Veeam / AWS S3 Object Lock Verification",
        "last_checked": timestamp,
        "is_simulated": True
    },
    {
        "control_id": "CTRL-SIEM-01",
        "asset_scope": "Enterprise-wide telemetry sources",
        "coverage_pct": 75.0,
        "evidence_ref": "Wazuh Manager + Graylog Log Ingestion Stream",
        "last_checked": timestamp,
        "is_simulated": False
    },
    {
        "control_id": "CTRL-PAM-01",
        "asset_scope": "Domain Controllers & Database Root logins",
        "coverage_pct": 55.0,
        "evidence_ref": "PAM Vault Session Activity Logs",
        "last_checked": timestamp,
        "is_simulated": True
    },
    {
        "control_id": "CTRL-DLP-01",
        "asset_scope": "Core Banking and Customer Support endpoints",
        "coverage_pct": 48.0,
        "evidence_ref": "Endpoint DLP Agent Report",
        "last_checked": timestamp,
        "is_simulated": True
    },
    {
        "control_id": "CTRL-API-01",
        "asset_scope": "External Partner UPI & Banking APIs",
        "coverage_pct": 65.0,
        "evidence_ref": "Kong API Gateway Audit Logs",
        "last_checked": timestamp,
        "is_simulated": False
    },
    {
        "control_id": "CTRL-IR-01",
        "asset_scope": "Organization Wide",
        "coverage_pct": 80.0,
        "evidence_ref": "CERT-In Empaneled Retainer Agreement & Tabletop Log",
        "last_checked": timestamp,
        "is_simulated": False
    }
]

scenarios = [
    {
        "id": "ransomware",
        "name": "Ransomware Outage & Operational Lockout",
        "threat_type": "Targeted Extortion Syndicate",
        "attack_techniques": ["T1486 Data Encrypted for Impact", "T1490 Inhibit System Recovery", "T1078 Valid Accounts"],
        "applicable_vulns": ["RCE", "Privilege Escalation"],
        "tef_params": {"low": 0.10, "likely": 0.35, "high": 0.90}
    },
    {
        "id": "data_breach",
        "name": "Customer Financial PII Exfiltration",
        "threat_type": "State-sponsored / Advanced Cybercrime",
        "attack_techniques": ["T1041 Exfiltration Over C2", "T1567 Exfiltration Over Web Service", "T1005 Data from Local System"],
        "applicable_vulns": ["SQLi", "Information Disclosure", "RCE"],
        "tef_params": {"low": 0.15, "likely": 0.40, "high": 0.85}
    },
    {
        "id": "credential_compromise",
        "name": "Privileged Domain / DB Account Takeover",
        "threat_type": "Credential Broker / Phishing",
        "attack_techniques": ["T1078 Valid Accounts", "T1555 Credentials from Password Stores"],
        "applicable_vulns": ["Credential Exposure", "Default Passwords"],
        "tef_params": {"low": 0.20, "likely": 0.60, "high": 1.20}
    },
    {
        "id": "webapp_compromise",
        "name": "Internet Banking API / Web Application Exploitation",
        "threat_type": "Opportunistic Web Exploiters",
        "attack_techniques": ["T1190 Exploit Public-Facing Application"],
        "applicable_vulns": ["RCE", "XSS", "SSRF", "Auth Bypass"],
        "tef_params": {"low": 0.25, "likely": 0.50, "high": 1.10}
    },
    {
        "id": "insider_misuse",
        "name": "Malicious Privileged Insider Unauthorized Extraction",
        "threat_type": "Disgruntled / Compromised Employee",
        "attack_techniques": ["T1087 Account Discovery", "T1530 Data from Cloud Storage Object"],
        "applicable_vulns": ["Weak Access Controls"],
        "tef_params": {"low": 0.05, "likely": 0.15, "high": 0.40}
    },
    {
        "id": "ddos_outage",
        "name": "Distributed Denial of Service on Payment Switch",
        "threat_type": "Hacktivist / Volumetric Botnet",
        "attack_techniques": ["T1498 Network Denial of Service", "T1499 Endpoint Denial of Service"],
        "applicable_vulns": ["Resource Exhaustion"],
        "tef_params": {"low": 0.30, "likely": 0.70, "high": 1.50}
    }
]

snapshot = {
    "snapshot_id": "snap-20260924-001",
    "timestamp": timestamp,
    "organization": {
        "name": "Apex FinCorp Ltd. (Simulated Indian NBFC)",
        "sector": "Non-Banking Financial Company (BFSI)",
        "regulators": ["RBI", "SEBI", "Data Protection Board of India (DPBI)"],
        "total_assets": len(assets),
        "risk_appetite_var95": 120000000.0,
        "annual_revenue": 4500000000.0
    },
    "services": services,
    "assets": assets,
    "cve_intel": cve_intel,
    "findings": findings,
    "wazuh_telemetry": wazuh_telemetry,
    "control_state": control_state,
    "scenarios": scenarios
}

output_path = "backend/app/data/seed_snapshot.json"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(snapshot, f, indent=2)

print(f"Seed snapshot saved to {output_path} with {len(assets)} assets and {len(findings)} findings.")
