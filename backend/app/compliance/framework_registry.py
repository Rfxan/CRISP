"""
Authoritative Framework Requirements Registry for CRISP Compliance Hub.
Defines every requirement/control clause across:
1. SEBI CSCRF 2024 (Cybersecurity and Cyber Resilience Framework, Circular Aug 20, 2024)
2. RBI Cyber Security Framework (Circular RBI/2015-16/418 & Master Directions)
3. NIST CSF 2.0 (NIST CSWP 29, Feb 2024)
4. ISO/IEC 27001:2022 (Annex A Controls)
5. CIS Controls v8 (Center for Internet Security 2021)
"""

from typing import Dict, Any, List

FRAMEWORK_REQUIREMENTS: Dict[str, List[Dict[str, Any]]] = {
    "sebi": [
        {
            "id": "SEBI-GOV-01",
            "clause": "Part 1, Cl. 4.1",
            "title": "Cybersecurity Governance & Board Steering Committee",
            "domain": "Govern",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Corporate governance policy & board charter requirement"
        },
        {
            "id": "SEBI-GOV-02",
            "clause": "Part 1, Cl. 4.2",
            "title": "Designation & Independence of Chief Information Security Officer (CISO)",
            "domain": "Govern",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Organizational staffing & reporting line mandate"
        },
        {
            "id": "SEBI-ID-01",
            "clause": "Part 2, Cl. 5.1",
            "title": "Hardware, Software & Critical System Inventory Management",
            "domain": "Identify",
            "mapped_control_id": "CTRL-HARD-01",
            "evidence_source": "Wazuh Agent Daemon Telemetry / Network Sniffer Inventory",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-ID-02",
            "clause": "Part 2, Cl. 5.2",
            "title": "Asset Classification & Criticality Categorization",
            "domain": "Identify",
            "mapped_control_id": "CTRL-HARD-01",
            "evidence_source": "CRISP Asset Criticality Schema (criticality_1_5 & business_service)",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-01",
            "clause": "Part 3, Cl. 6.1",
            "title": "Multi-Factor Authentication (MFA) for Administrative Access",
            "domain": "Protect",
            "mapped_control_id": "CTRL-MFA-01",
            "evidence_source": "Keycloak IAM / Active Directory FIDO2 Authentication Logs",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-02",
            "clause": "Part 3, Cl. 6.2",
            "title": "Privileged Access Management (PAM) & Session Recording",
            "domain": "Protect",
            "mapped_control_id": "CTRL-PAM-01",
            "evidence_source": "PAM Vault Audit Log / Bastion Session Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-03",
            "clause": "Part 3, Cl. 6.3",
            "title": "Network Micro-Segmentation & Critical Zone Isolation",
            "domain": "Protect",
            "mapped_control_id": "CTRL-SEG-01",
            "evidence_source": "Cloud VPC Security Groups / Firewall Ingress Logs",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-04",
            "clause": "Part 3, Cl. 6.4",
            "title": "Web Application & API Protection (WAAP / WAF + DDoS Mitigation)",
            "domain": "Protect",
            "mapped_control_id": "CTRL-WAF-01",
            "evidence_source": "Cloudflare / AWS WAF Blocked Request Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-05",
            "clause": "Part 3, Cl. 6.5",
            "title": "API Gateway Security, Token Inspection & Schema Validation",
            "domain": "Protect",
            "mapped_control_id": "CTRL-API-01",
            "evidence_source": "API Security Gateway / Kong / Apigee Audit Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-06",
            "clause": "Part 3, Cl. 6.6",
            "title": "Vulnerability Management & Timely Patching (7-day SLA for KEV)",
            "domain": "Protect",
            "mapped_control_id": "CTRL-PATCH-01",
            "evidence_source": "OpenVAS / Nessus Scan Feeds & CISA KEV Intelligence",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-07",
            "clause": "Part 3, Cl. 6.7",
            "title": "Endpoint Detection & Response (EDR) on all Regulated Assets",
            "domain": "Protect",
            "mapped_control_id": "CTRL-EDR-01",
            "evidence_source": "Microsoft Defender EDR / Wazuh Host Agent Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-08",
            "clause": "Part 3, Cl. 6.8",
            "title": "Encryption of Sensitive Financial & Personal Data at Rest and Transit",
            "domain": "Protect",
            "mapped_control_id": "CTRL-ENC-01",
            "evidence_source": "Database TDE / KMS HSM Key Rotation Audit Logs",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-09",
            "clause": "Part 3, Cl. 6.9",
            "title": "Data Loss Prevention (DLP) across Endpoints, Network & Egress",
            "domain": "Protect",
            "mapped_control_id": "CTRL-DLP-01",
            "evidence_source": "Enterprise DLP Agent Policy Block Records",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-10",
            "clause": "Part 3, Cl. 6.10",
            "title": "Hardening Baselines & CIS Benchmark Configuration Auditing",
            "domain": "Protect",
            "mapped_control_id": "CTRL-HARD-01",
            "evidence_source": "Wazuh SCA (Security Configuration Assessment) Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-PROT-11",
            "clause": "Part 3, Cl. 6.11",
            "title": "Employee Cybersecurity Awareness & Phishing Simulation Drills",
            "domain": "Protect",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Human resource training & operational awareness activity"
        },
        {
            "id": "SEBI-PROT-12",
            "clause": "Part 3, Cl. 6.12",
            "title": "Physical Security of Data Centers & Critical Facilities",
            "domain": "Protect",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Physical facility access control (CCTV, biometric turnstiles)"
        },
        {
            "id": "SEBI-DET-01",
            "clause": "Part 4, Cl. 7.1",
            "title": "Centralized 24x7 Security Operations Centre (SOC) & SIEM",
            "domain": "Detect",
            "mapped_control_id": "CTRL-SIEM-01",
            "evidence_source": "Centralized Wazuh/ELK SIEM Event Ingestion Stream",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-DET-02",
            "clause": "Part 4, Cl. 7.2",
            "title": "Continuous Behavioral Anomaly Detection & Threat Hunting",
            "domain": "Detect",
            "mapped_control_id": "CTRL-ANOM-01",
            "evidence_source": "CRISP Isolation Forest Anomaly Engine & Threat Intelligence",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-DET-03",
            "clause": "Part 4, Cl. 7.3",
            "title": "Statutory 6-Hour Incident Notification Capability",
            "domain": "Detect",
            "mapped_control_id": "CTRL-SIEM-01",
            "evidence_source": "SEBI CSCRF 6-Hour Incident Triage Readiness Metric",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-RESP-01",
            "clause": "Part 5, Cl. 8.1",
            "title": "Incident Response Plan & CERT-In Empaneled Retainer SLA",
            "domain": "Respond",
            "mapped_control_id": "CTRL-IR-01",
            "evidence_source": "CERT-In Retainer SLA Agreement & Incident Playbook",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-RESP-02",
            "clause": "Part 5, Cl. 8.2",
            "title": "Regulatory Reporting & Forensic Triage Execution",
            "domain": "Respond",
            "mapped_control_id": "CTRL-IR-01",
            "evidence_source": "Forensic Readiness Checklist & Regulatory Incident Logging",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-REC-01",
            "clause": "Part 5, Cl. 9.1",
            "title": "Immutable & Air-Gapped Data Backup Infrastructure",
            "domain": "Recover",
            "mapped_control_id": "CTRL-BKP-01",
            "evidence_source": "WORM / S3 Object Lock Immutable Backup Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-REC-02",
            "clause": "Part 5, Cl. 9.2",
            "title": "4-Hour Recovery Time Objective (RTO) Restoration Drills",
            "domain": "Recover",
            "mapped_control_id": "CTRL-BKP-01",
            "evidence_source": "Disaster Recovery Drill Evidence & RTO Attestation",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-TPRM-01",
            "clause": "Part 6, Cl. 10.1",
            "title": "Third-Party Vendor Risk Assessment & API Sandboxing",
            "domain": "TPRM",
            "mapped_control_id": "CTRL-TPRM-01",
            "evidence_source": "Vendor Onboarding Wizard & Telemetry Configuration Store",
            "unmapped_reason": None
        },
        {
            "id": "SEBI-AUD-01",
            "clause": "Part 7, Cl. 11.1",
            "title": "Periodic VAPT & Independent Third-Party Cyber Audit",
            "domain": "Assurance",
            "mapped_control_id": "CTRL-VAPT-01",
            "evidence_source": "Independent CERT-In VAPT Audit Report & Attestation",
            "unmapped_reason": None
        }
    ],

    "rbi": [
        {
            "id": "RBI-CSF-01",
            "clause": "Annex 1, Cl. 1",
            "title": "Inventory Management of Business IT Assets & Classifications",
            "domain": "Inventory",
            "mapped_control_id": "CTRL-HARD-01",
            "evidence_source": "CRISP Asset Schema & Network Telemetry Verification",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-02",
            "clause": "Annex 1, Cl. 2",
            "title": "Preventing Unauthorized Software & Application Whitelisting",
            "domain": "Endpoint",
            "mapped_control_id": "CTRL-EDR-01",
            "evidence_source": "Microsoft Defender Application Control / Wazuh Syscheck",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-03",
            "clause": "Annex 1, Cl. 3",
            "title": "Physical and Environmental Security Controls",
            "domain": "Physical",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Physical premises protection (UPS, fire suppression, biometric gates)"
        },
        {
            "id": "RBI-CSF-04",
            "clause": "Annex 1, Cl. 4",
            "title": "Network Management, Security Zoning & Core Switch Isolation",
            "domain": "Network",
            "mapped_control_id": "CTRL-SEG-01",
            "evidence_source": "Core Banking Network Micro-Segmentation Policies",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-05",
            "clause": "Annex 1, Cl. 5",
            "title": "Secure Configuration & System Hardening Standards",
            "domain": "Configuration",
            "mapped_control_id": "CTRL-HARD-01",
            "evidence_source": "CIS Benchmark Hardening Audit Logs",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-06",
            "clause": "Annex 1, Cl. 6",
            "title": "Anti-Virus & Automated Patch Management for Known Vulnerabilities",
            "domain": "Vulnerability",
            "mapped_control_id": "CTRL-PATCH-01",
            "evidence_source": "Vulnerability Scanner Telemetry & Patch Verification",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-07",
            "clause": "Annex 1, Cl. 7.1",
            "title": "Privileged Access Management (PAM) for Elevated Accounts",
            "domain": "Access",
            "mapped_control_id": "CTRL-PAM-01",
            "evidence_source": "PAM Session Vault Audit Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-08",
            "clause": "Annex 1, Cl. 7.2",
            "title": "Multi-Factor Authentication for Remote & Privileged Access",
            "domain": "Access",
            "mapped_control_id": "CTRL-MFA-01",
            "evidence_source": "FIDO2 / Hardware Token Authentication Records",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-09",
            "clause": "Annex 1, Cl. 7.3",
            "title": "Removable Media Usage Restrictions & Port Blocking",
            "domain": "Access",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Operational physical endpoint policy for removable USB drives"
        },
        {
            "id": "RBI-CSF-10",
            "clause": "Annex 1, Cl. 8.1",
            "title": "Protection of Customer Financial Data (Encryption at Rest & Transit)",
            "domain": "Data",
            "mapped_control_id": "CTRL-ENC-01",
            "evidence_source": "Database TDE & HSM Encryption Key Attestation",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-11",
            "clause": "Annex 1, Cl. 8.2",
            "title": "Data Loss Prevention (DLP) across Internet Banking Systems",
            "domain": "Data",
            "mapped_control_id": "CTRL-DLP-01",
            "evidence_source": "Endpoint & Network DLP Enforcement Logs",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-12",
            "clause": "Annex 1, Cl. 9",
            "title": "Boundary Defense & Web Application Firewall for Internet Banking",
            "domain": "Perimeter",
            "mapped_control_id": "CTRL-WAF-01",
            "evidence_source": "WAF & DDoS Mitigation Appliance Logs",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-13",
            "clause": "Annex 1, Cl. 10",
            "title": "Application Security Testing & Secure Open Banking APIs",
            "domain": "Application",
            "mapped_control_id": "CTRL-API-01",
            "evidence_source": "API Security Gateway Inspection & DAST Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-14",
            "clause": "Annex 1, Cl. 11",
            "title": "Immutable Backups & Periodic Restoration Verification",
            "domain": "Resilience",
            "mapped_control_id": "CTRL-BKP-01",
            "evidence_source": "Automated Immutable Backup & Restoration Check",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-15",
            "clause": "Annex 1, Cl. 12",
            "title": "Security Operations Centre (SOC) 24x7 Continuous Monitoring",
            "domain": "Operations",
            "mapped_control_id": "CTRL-SIEM-01",
            "evidence_source": "Wazuh SIEM Continuous Alert Monitoring",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-16",
            "clause": "Annex 1, Cl. 13",
            "title": "Incident Management, Forensics & Cyber Crisis Management (CCMP)",
            "domain": "Response",
            "mapped_control_id": "CTRL-IR-01",
            "evidence_source": "CCMP Playbook & CERT-In Reporting Channel",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-17",
            "clause": "Annex 1, Cl. 14",
            "title": "Periodic VAPT & Red-Teaming Exercises by Empaneled Auditors",
            "domain": "Assurance",
            "mapped_control_id": "CTRL-VAPT-01",
            "evidence_source": "External Red Team Assessment & Remediation Report",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-18",
            "clause": "Annex 1, Cl. 15",
            "title": "Vendor / Third-Party Cyber Risk Management & Due Diligence",
            "domain": "TPRM",
            "mapped_control_id": "CTRL-TPRM-01",
            "evidence_source": "CRISP Vendor Management & Questionnaire Attestation",
            "unmapped_reason": None
        },
        {
            "id": "RBI-CSF-19",
            "clause": "Annex 1, Cl. 16",
            "title": "Cybersecurity Training & Awareness for Bank Employees",
            "domain": "Training",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Internal HR employee training curriculum and records"
        },
        {
            "id": "RBI-CSF-20",
            "clause": "Annex 1, Cl. 17",
            "title": "Customer Cybersecurity Education & Awareness Campaigns",
            "domain": "Outreach",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Public outreach and customer education initiatives"
        }
    ],

    "nist": [
        {
            "id": "NIST-GV-01",
            "clause": "GV.OC-01",
            "title": "Organizational Mission & Risk Context",
            "domain": "Govern",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Enterprise governance & organizational mission documentation"
        },
        {
            "id": "NIST-GV-02",
            "clause": "GV.RR-01",
            "title": "Cybersecurity Roles and Responsibilities",
            "domain": "Govern",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "HR roles, responsibilities, and accountability assignments"
        },
        {
            "id": "NIST-GV-03",
            "clause": "GV.SC-04",
            "title": "Cybersecurity Supply Chain Risk Management",
            "domain": "Govern",
            "mapped_control_id": "CTRL-TPRM-01",
            "evidence_source": "Vendor Security Assessment Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "NIST-ID-01",
            "clause": "ID.AM-01",
            "title": "Physical and Software Asset Inventories",
            "domain": "Identify",
            "mapped_control_id": "CTRL-HARD-01",
            "evidence_source": "CRISP Asset Schema & Network Telemetry Verification",
            "unmapped_reason": None
        },
        {
            "id": "NIST-ID-02",
            "clause": "ID.RA-01",
            "title": "Vulnerability Identification & Risk Assessment",
            "domain": "Identify",
            "mapped_control_id": "CTRL-PATCH-01",
            "evidence_source": "OpenVAS / Nessus Scans & FIRST EPSS Intelligence",
            "unmapped_reason": None
        },
        {
            "id": "NIST-PR-01",
            "clause": "PR.AA-01",
            "title": "Identity Management, Credentials & Access Authentication",
            "domain": "Protect",
            "mapped_control_id": "CTRL-MFA-01",
            "evidence_source": "Keycloak IAM / FIDO2 Authentication Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "NIST-PR-02",
            "clause": "PR.AA-05",
            "title": "Privileged Access Management & Credential Vaulting",
            "domain": "Protect",
            "mapped_control_id": "CTRL-PAM-01",
            "evidence_source": "PAM Bastion Vault Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "NIST-PR-03",
            "clause": "PR.IR-01",
            "title": "Network Micro-Segmentation & Boundary Isolation",
            "domain": "Protect",
            "mapped_control_id": "CTRL-SEG-01",
            "evidence_source": "Network Security Group & Routing Ingress Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "NIST-PR-04",
            "clause": "PR.IR-02",
            "title": "Web Application Perimeter Defense (WAF)",
            "domain": "Protect",
            "mapped_control_id": "CTRL-WAF-01",
            "evidence_source": "Cloud WAF Ingress Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "NIST-PR-05",
            "clause": "PR.DS-01",
            "title": "Confidentiality & Integrity of Data-at-Rest (Encryption)",
            "domain": "Protect",
            "mapped_control_id": "CTRL-ENC-01",
            "evidence_source": "Database Transparent Data Encryption & KMS Logs",
            "unmapped_reason": None
        },
        {
            "id": "NIST-PR-06",
            "clause": "PR.DS-10",
            "title": "Protection Against Unauthorized Data Exfiltration (DLP)",
            "domain": "Protect",
            "mapped_control_id": "CTRL-DLP-01",
            "evidence_source": "Enterprise DLP Endpoint & Network Enforcement",
            "unmapped_reason": None
        },
        {
            "id": "NIST-PR-07",
            "clause": "PR.PS-01",
            "title": "Configuration Baselines & System Hardening",
            "domain": "Protect",
            "mapped_control_id": "CTRL-HARD-01",
            "evidence_source": "CIS Benchmark Configuration Auditing",
            "unmapped_reason": None
        },
        {
            "id": "NIST-PR-08",
            "clause": "PR.PS-06",
            "title": "Secure Software Development & API Protection",
            "domain": "Protect",
            "mapped_control_id": "CTRL-API-01",
            "evidence_source": "API Security Gateway Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "NIST-PR-09",
            "clause": "PR.AT-01",
            "title": "Workforce Cybersecurity Awareness & Skills Training",
            "domain": "Protect",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Personnel security awareness and phishing training tracking"
        },
        {
            "id": "NIST-DE-01",
            "clause": "DE.CM-01",
            "title": "Continuous Network & Asset Log Centralization",
            "domain": "Detect",
            "mapped_control_id": "CTRL-SIEM-01",
            "evidence_source": "Wazuh SIEM Central Log Aggregator",
            "unmapped_reason": None
        },
        {
            "id": "NIST-DE-02",
            "clause": "DE.CM-06",
            "title": "Endpoint Malicious Code & Host EDR Monitoring",
            "domain": "Detect",
            "mapped_control_id": "CTRL-EDR-01",
            "evidence_source": "Microsoft Defender for Endpoint Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "NIST-DE-03",
            "clause": "DE.AE-02",
            "title": "Behavioral Anomaly Analysis & Threat Intelligence Correlation",
            "domain": "Detect",
            "mapped_control_id": "CTRL-ANOM-01",
            "evidence_source": "Isolation Forest Anomaly Engine & Threat Feeds",
            "unmapped_reason": None
        },
        {
            "id": "NIST-RS-01",
            "clause": "RS.MA-01",
            "title": "Incident Management Execution & Stakeholder Coordination",
            "domain": "Respond",
            "mapped_control_id": "CTRL-IR-01",
            "evidence_source": "CERT-In Retainer & Incident Playbook",
            "unmapped_reason": None
        },
        {
            "id": "NIST-RC-01",
            "clause": "RC.RP-01",
            "title": "Recovery Plan Execution & Immutable Backup Restoration",
            "domain": "Recover",
            "mapped_control_id": "CTRL-BKP-01",
            "evidence_source": "Immutable Backup Validation & DR Sandbox Drills",
            "unmapped_reason": None
        }
    ],

    "iso": [
        {
            "id": "ISO-A.5.15",
            "clause": "A.5.15",
            "title": "Access Control Policies & Privileged Authorization",
            "domain": "Organizational",
            "mapped_control_id": "CTRL-PAM-01",
            "evidence_source": "PAM Session Auditing Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.5.19",
            "clause": "A.5.19",
            "title": "Information Security in Supplier Relationships",
            "domain": "Organizational",
            "mapped_control_id": "CTRL-TPRM-01",
            "evidence_source": "Third-Party Risk Assessment Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.5.24",
            "clause": "A.5.24",
            "title": "Information Security Incident Management Planning",
            "domain": "Organizational",
            "mapped_control_id": "CTRL-IR-01",
            "evidence_source": "Incident Response Retainer & Playbook",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.5.30",
            "clause": "A.5.30",
            "title": "ICT Readiness for Business Continuity",
            "domain": "Organizational",
            "mapped_control_id": "CTRL-BKP-01",
            "evidence_source": "Disaster Recovery Drill Evidence",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.6.1",
            "clause": "A.6.1",
            "title": "Candidate Screening & Employment Background Checks",
            "domain": "People",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Human resources pre-employment verification procedures"
        },
        {
            "id": "ISO-A.6.3",
            "clause": "A.6.3",
            "title": "Information Security Awareness, Education and Training",
            "domain": "People",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Annual corporate security training tracking"
        },
        {
            "id": "ISO-A.7.1",
            "clause": "A.7.1",
            "title": "Physical Security Perimeters & Data Center Barriers",
            "domain": "Physical",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Physical perimeter security (fencing, access cards, guards)"
        },
        {
            "id": "ISO-A.7.4",
            "clause": "A.7.4",
            "title": "Physical Security Monitoring (CCTV & Environmental Alarms)",
            "domain": "Physical",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Surveillance system video retention and power/cooling telemetry"
        },
        {
            "id": "ISO-A.8.1",
            "clause": "A.8.1",
            "title": "User Endpoint Device Security & Management",
            "domain": "Technological",
            "mapped_control_id": "CTRL-EDR-01",
            "evidence_source": "Microsoft Defender EDR Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.2",
            "clause": "A.8.2",
            "title": "Privileged Access Rights & Vault Management",
            "domain": "Technological",
            "mapped_control_id": "CTRL-PAM-01",
            "evidence_source": "PAM Bastion Vault Access Logs",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.5",
            "clause": "A.8.5",
            "title": "Secure Authentication (Multi-Factor Authentication)",
            "domain": "Technological",
            "mapped_control_id": "CTRL-MFA-01",
            "evidence_source": "Keycloak IAM FIDO2 Records",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.7",
            "clause": "A.8.7",
            "title": "Protection Against Malware (Anti-Malware & EDR)",
            "domain": "Technological",
            "mapped_control_id": "CTRL-EDR-01",
            "evidence_source": "EDR Active Malware Detection Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.8",
            "clause": "A.8.8",
            "title": "Management of Technical Vulnerabilities (Patching)",
            "domain": "Technological",
            "mapped_control_id": "CTRL-PATCH-01",
            "evidence_source": "OpenVAS / Nessus Vulnerability Feeds",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.9",
            "clause": "A.8.9",
            "title": "Configuration Management & Systems Hardening",
            "domain": "Technological",
            "mapped_control_id": "CTRL-HARD-01",
            "evidence_source": "Wazuh CIS Benchmark Assessments",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.12",
            "clause": "A.8.12",
            "title": "Data Leakage Prevention (DLP)",
            "domain": "Technological",
            "mapped_control_id": "CTRL-DLP-01",
            "evidence_source": "Enterprise DLP Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.13",
            "clause": "A.8.13",
            "title": "Information Backup & Immutable Retention",
            "domain": "Technological",
            "mapped_control_id": "CTRL-BKP-01",
            "evidence_source": "Immutable Backup Validation Logs",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.15",
            "clause": "A.8.15",
            "title": "Logging & Audit Trail Management",
            "domain": "Technological",
            "mapped_control_id": "CTRL-SIEM-01",
            "evidence_source": "Wazuh SIEM Central Log Retention",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.16",
            "clause": "A.8.16",
            "title": "Monitoring Activities & Anomaly Detection",
            "domain": "Technological",
            "mapped_control_id": "CTRL-ANOM-01",
            "evidence_source": "Isolation Forest Anomaly Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.20",
            "clause": "A.8.20",
            "title": "Network Security & Web Application Filtering",
            "domain": "Technological",
            "mapped_control_id": "CTRL-WAF-01",
            "evidence_source": "WAF & DDoS Mitigation Appliance Logs",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.24",
            "clause": "A.8.24",
            "title": "Use of Cryptography & Key Management",
            "domain": "Technological",
            "mapped_control_id": "CTRL-ENC-01",
            "evidence_source": "Database TDE & KMS HSM Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.26",
            "clause": "A.8.26",
            "title": "Application Security Requirements & Secure APIs",
            "domain": "Technological",
            "mapped_control_id": "CTRL-API-01",
            "evidence_source": "API Security Gateway Inspection",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.31",
            "clause": "A.8.31",
            "title": "Separation of Development, Test and Production Environments",
            "domain": "Technological",
            "mapped_control_id": "CTRL-SEG-01",
            "evidence_source": "VPC & Micro-Segmentation Firewall Ingress Logs",
            "unmapped_reason": None
        },
        {
            "id": "ISO-A.8.34",
            "clause": "A.8.34",
            "title": "Independent Technical Security Assessment (VAPT)",
            "domain": "Technological",
            "mapped_control_id": "CTRL-VAPT-01",
            "evidence_source": "Periodic External Penetration Testing Reports",
            "unmapped_reason": None
        }
    ],

    "cis": [
        {
            "id": "CIS-01",
            "clause": "CIS Control 1",
            "title": "Inventory and Control of Enterprise Assets",
            "domain": "Hygiene",
            "mapped_control_id": "CTRL-HARD-01",
            "evidence_source": "CRISP Asset Schema & Network Telemetry Verification",
            "unmapped_reason": None
        },
        {
            "id": "CIS-02",
            "clause": "CIS Control 2",
            "title": "Inventory and Control of Software Assets",
            "domain": "Hygiene",
            "mapped_control_id": "CTRL-PATCH-01",
            "evidence_source": "OpenVAS / Nessus Vulnerability Scanning Feeds",
            "unmapped_reason": None
        },
        {
            "id": "CIS-03",
            "clause": "CIS Control 3",
            "title": "Data Protection (Encryption & Data Loss Prevention)",
            "domain": "Data",
            "mapped_control_id": "CTRL-ENC-01",
            "evidence_source": "Database TDE & Enterprise DLP Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "CIS-04",
            "clause": "CIS Control 4",
            "title": "Secure Configuration of Enterprise Assets and Software",
            "domain": "Configuration",
            "mapped_control_id": "CTRL-HARD-01",
            "evidence_source": "CIS Benchmark Configuration Auditing",
            "unmapped_reason": None
        },
        {
            "id": "CIS-05",
            "clause": "CIS Control 5",
            "title": "Account Management & Privileged Credential Control",
            "domain": "Access",
            "mapped_control_id": "CTRL-PAM-01",
            "evidence_source": "PAM Session Vault Audit Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "CIS-06",
            "clause": "CIS Control 6",
            "title": "Access Control Management (Multi-Factor Authentication)",
            "domain": "Access",
            "mapped_control_id": "CTRL-MFA-01",
            "evidence_source": "Keycloak IAM FIDO2 Records",
            "unmapped_reason": None
        },
        {
            "id": "CIS-07",
            "clause": "CIS Control 7",
            "title": "Continuous Vulnerability Management",
            "domain": "Vulnerability",
            "mapped_control_id": "CTRL-PATCH-01",
            "evidence_source": "OpenVAS Scan Ingestion & Threat Feeds",
            "unmapped_reason": None
        },
        {
            "id": "CIS-08",
            "clause": "CIS Control 8",
            "title": "Audit Log Management & Centralized SIEM",
            "domain": "Operations",
            "mapped_control_id": "CTRL-SIEM-01",
            "evidence_source": "Wazuh SIEM Central Log Retention",
            "unmapped_reason": None
        },
        {
            "id": "CIS-09",
            "clause": "CIS Control 9",
            "title": "Email and Web Browser Protections (WAF & Egress Defense)",
            "domain": "Perimeter",
            "mapped_control_id": "CTRL-WAF-01",
            "evidence_source": "Cloud WAF Ingress Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "CIS-10",
            "clause": "CIS Control 10",
            "title": "Malware Defenses (Endpoint Detection & Response)",
            "domain": "Endpoint",
            "mapped_control_id": "CTRL-EDR-01",
            "evidence_source": "Microsoft Defender EDR Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "CIS-11",
            "clause": "CIS Control 11",
            "title": "Data Recovery (Air-Gapped Immutable Backups)",
            "domain": "Resilience",
            "mapped_control_id": "CTRL-BKP-01",
            "evidence_source": "Immutable Backup Validation & DR Sandbox Drills",
            "unmapped_reason": None
        },
        {
            "id": "CIS-12",
            "clause": "CIS Control 12",
            "title": "Network Infrastructure Management (Micro-Segmentation)",
            "domain": "Network",
            "mapped_control_id": "CTRL-SEG-01",
            "evidence_source": "VPC & Micro-Segmentation Firewall Ingress Logs",
            "unmapped_reason": None
        },
        {
            "id": "CIS-13",
            "clause": "CIS Control 13",
            "title": "Network Monitoring and Defense (Anomaly Detection)",
            "domain": "Operations",
            "mapped_control_id": "CTRL-ANOM-01",
            "evidence_source": "Isolation Forest Anomaly Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "CIS-14",
            "clause": "CIS Control 14",
            "title": "Security Awareness and Skills Training",
            "domain": "Training",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Personnel training curriculum and social engineering testing"
        },
        {
            "id": "CIS-15",
            "clause": "CIS Control 15",
            "title": "Service Provider Management (Third-Party Risk)",
            "domain": "TPRM",
            "mapped_control_id": "CTRL-TPRM-01",
            "evidence_source": "Third-Party Vendor Risk Assessment Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "CIS-16",
            "clause": "CIS Control 16",
            "title": "Application Software Security (Secure APIs)",
            "domain": "Application",
            "mapped_control_id": "CTRL-API-01",
            "evidence_source": "API Security Gateway Inspection",
            "unmapped_reason": None
        },
        {
            "id": "CIS-17",
            "clause": "CIS Control 17",
            "title": "Incident Response Management",
            "domain": "Response",
            "mapped_control_id": "CTRL-IR-01",
            "evidence_source": "Incident Response Retainer & Playbook",
            "unmapped_reason": None
        },
        {
            "id": "CIS-18",
            "clause": "CIS Control 18",
            "title": "Penetration Testing (Independent VAPT)",
            "domain": "Assurance",
            "mapped_control_id": "CTRL-VAPT-01",
            "evidence_source": "Periodic External Penetration Testing Reports",
            "unmapped_reason": None
        }
    ],
    "dpdp": [
        {
            "id": "DPDP-01",
            "clause": "Section 5",
            "title": "Notice and Transparency in Personal Data Processing",
            "domain": "Transparency",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Data principal itemized notice & multilingual presentation layer"
        },
        {
            "id": "DPDP-02",
            "clause": "Section 6",
            "title": "Verifiable Consent Architecture & Withdrawal Mechanism",
            "domain": "Consent",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Consent Manager API integration & user opt-out revocation pipeline"
        },
        {
            "id": "DPDP-03",
            "clause": "Section 8(1)",
            "title": "Data Accuracy, Completeness & Consistency of Personal Data",
            "domain": "Governance",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Master data management & database validation procedures"
        },
        {
            "id": "DPDP-04",
            "clause": "Section 8(5)",
            "title": "Reasonable Security Safeguards: Cryptographic Protection at Rest & Transit",
            "domain": "Security",
            "mapped_control_id": "CTRL-ENC-01",
            "evidence_source": "HSM Key Management & AES-256 Storage Volumes Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "DPDP-05",
            "clause": "Section 8(5)",
            "title": "Reasonable Security Safeguards: Data Loss Prevention & Exfiltration Controls",
            "domain": "Security",
            "mapped_control_id": "CTRL-DLP-01",
            "evidence_source": "Endpoint/Network DLP Egress Filters & Policy Violation Telemetry",
            "unmapped_reason": None
        },
        {
            "id": "DPDP-06",
            "clause": "Section 8(5)",
            "title": "Reasonable Security Safeguards: Multi-Factor Authentication & Access Controls",
            "domain": "Security",
            "mapped_control_id": "CTRL-MFA-01",
            "evidence_source": "Enterprise IAM FIDO2 / TOTP Enforcement Logs",
            "unmapped_reason": None
        },
        {
            "id": "DPDP-07",
            "clause": "Section 8(6)",
            "title": "Mandatory Personal Data Breach Notification to DPBI & Data Principals",
            "domain": "Breach Response",
            "mapped_control_id": "CTRL-IR-01",
            "evidence_source": "CSIRP Playbook & CERT-In / DPBI Notification Retainer Protocol",
            "unmapped_reason": None
        },
        {
            "id": "DPDP-08",
            "clause": "Section 8(7)",
            "title": "Purpose Limitation, Data Minimization & Secure Erasure Upon Completion",
            "domain": "Governance",
            "mapped_control_id": "CTRL-DLP-01",
            "evidence_source": "Automated Data Retention & Cryptographic Sanitization Verification",
            "unmapped_reason": None
        },
        {
            "id": "DPDP-09",
            "clause": "Section 9",
            "title": "Restrictions on Processing Personal Data of Children & Verification of Parental Consent",
            "domain": "Privacy",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Verifiable age assurance gating & behavioral tracking prohibition"
        },
        {
            "id": "DPDP-10",
            "clause": "Section 10(1)",
            "title": "Significant Data Fiduciary (SDF): Data Protection Impact Assessment (DPIA) & Audit",
            "domain": "Assurance",
            "mapped_control_id": "CTRL-VAPT-01",
            "evidence_source": "Periodic Privacy Audit & Independent VAPT / Security Review Reports",
            "unmapped_reason": None
        },
        {
            "id": "DPDP-11",
            "clause": "Section 10(2)",
            "title": "SDF: Designation of India-Based Data Protection Officer (DPO)",
            "domain": "Governance",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Corporate appointment of statutory DPO answering to Board"
        },
        {
            "id": "DPDP-12",
            "clause": "Section 11",
            "title": "Data Principal Right to Access Information & Summary of Processing",
            "domain": "Rights",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Data Subject Access Request (DSAR) self-service portal"
        },
        {
            "id": "DPDP-13",
            "clause": "Section 12",
            "title": "Data Principal Right to Correction, Completion, Updating and Erasure",
            "domain": "Rights",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "DSAR remediation workflow across backend databases"
        },
        {
            "id": "DPDP-14",
            "clause": "Section 13",
            "title": "Right of Grievance Redressal Mechanism & Appellate Filing",
            "domain": "Rights",
            "mapped_control_id": None,
            "evidence_source": None,
            "unmapped_reason": "Statutory Grievance Redressal ticketing and escalation channel"
        }
    ]
}
