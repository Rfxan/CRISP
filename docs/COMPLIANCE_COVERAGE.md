# CRISP Compliance Framework Coverage & Traceability Report

> **Audit Transparency Attestation**: Percentages in this document are computed directly from the canonical framework requirement mapping tables. CRISP strictly reports honest mapping coverage; no framework claims 100% unless genuinely 100% of all administrative, physical, and technical requirements are backed by automated telemetry.

*Report generated: 2026-09-29 UTC | Engine: CRISP FrameworkEngine v2.4*

---

## Executive Coverage Summary

| Framework | Canonical ID | Official Citation | Total Controls | Mapped | Unmapped | Mapping Coverage |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **SEBI CSCRF** | `sebi` | *SEBI Circular SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113 (Aug 20, 2024)* | 25 | 21 | 4 | **84.0%** |
| **RBI Cyber Security Framework** | `rbi` | *RBI Circular RBI/2015-16/418 & Master Directions on IT Governance* | 20 | 16 | 4 | **80.0%** |
| **NIST CSF 2.0** | `nist` | *NIST CSWP 29 (Feb 2024)* | 19 | 16 | 3 | **84.2%** |
| **ISO/IEC 27001:2022** | `iso` | *ISO/IEC 27001:2022 Information security, cybersecurity and privacy protection* | 23 | 19 | 4 | **82.6%** |
| **CIS Controls v8** | `cis` | *CIS Controls v8 (Center for Internet Security 2021)* | 18 | 17 | 1 | **94.4%** |

---

## SEBI CSCRF (84.0% Mapped)

- **Citation**: SEBI Circular SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113 (Aug 20, 2024)
- **Description**: Cybersecurity and Cyber Resilience Framework for Regulated Entities
- **Scope**: **21** mapped controls / **25** total requirements (**4** unmapped)

| Requirement ID | Framework Clause | Requirement Title | Domain | Mapping Status | CRISP Control ID | Audit Evidence / Telemetry Source |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| `SEBI-GOV-01` | **Part 1, Cl. 4.1** | Cybersecurity Governance & Board Steering Committee | Govern | [Unmapped] | *None (Out of Scope)* | *Corporate governance policy & board charter requirement* |
| `SEBI-GOV-02` | **Part 1, Cl. 4.2** | Designation & Independence of Chief Information Security Officer (CISO) | Govern | [Unmapped] | *None (Out of Scope)* | *Organizational staffing & reporting line mandate* |
| `SEBI-ID-01` | **Part 2, Cl. 5.1** | Hardware, Software & Critical System Inventory Management | Identify | [Mapped] | `CTRL-HARD-01` (Automated CIS Benchmark Configuration Auditing & Host Hardening) | Wazuh Agent Daemon Telemetry / Network Sniffer Inventory |
| `SEBI-ID-02` | **Part 2, Cl. 5.2** | Asset Classification & Criticality Categorization | Identify | [Mapped] | `CTRL-HARD-01` (Automated CIS Benchmark Configuration Auditing & Host Hardening) | CRISP Asset Criticality Schema (criticality_1_5 & business_service) |
| `SEBI-PROT-01` | **Part 3, Cl. 6.1** | Multi-Factor Authentication (MFA) for Administrative Access | Protect | [Mapped] | `CTRL-MFA-01` (Privileged Access Multi-Factor Authentication (FIDO2 / Hardware Token)) | Keycloak IAM / Active Directory FIDO2 Authentication Logs |
| `SEBI-PROT-02` | **Part 3, Cl. 6.2** | Privileged Access Management (PAM) & Session Recording | Protect | [Mapped] | `CTRL-PAM-01` (Privileged Access Management (PAM) Vault with Just-in-Time Session Recording) | PAM Vault Audit Log / Bastion Session Telemetry |
| `SEBI-PROT-03` | **Part 3, Cl. 6.3** | Network Micro-Segmentation & Critical Zone Isolation | Protect | [Mapped] | `CTRL-SEG-01` (Zero Trust Micro-Segmentation (Payment Core & DB Isolation)) | Cloud VPC Security Groups / Firewall Ingress Logs |
| `SEBI-PROT-04` | **Part 3, Cl. 6.4** | Web Application & API Protection (WAAP / WAF + DDoS Mitigation) | Protect | [Mapped] | `CTRL-WAF-01` (Cloud-Native Web Application & API Protection (WAAP / WAF + DDoS Mitigation)) | Cloudflare / AWS WAF Blocked Request Telemetry |
| `SEBI-PROT-05` | **Part 3, Cl. 6.5** | API Gateway Security, Token Inspection & Schema Validation | Protect | [Mapped] | `CTRL-API-01` (API Security Gateway with Machine Learning Behavioral Anomaly Detection) | API Security Gateway / Kong / Apigee Audit Telemetry |
| `SEBI-PROT-06` | **Part 3, Cl. 6.6** | Vulnerability Management & Timely Patching (7-day SLA for KEV) | Protect | [Mapped] | `CTRL-PATCH-01` (Automated Vulnerability Management & Patch Deployment Pipeline (SLA: 7 days for KEV)) | OpenVAS / Nessus Scan Feeds & CISA KEV Intelligence |
| `SEBI-PROT-07` | **Part 3, Cl. 6.7** | Endpoint Detection & Response (EDR) on all Regulated Assets | Protect | [Mapped] | `CTRL-EDR-01` (Next-Gen Endpoint Detection & Response (EDR) + Managed SOC (Wazuh/MDR)) | Microsoft Defender EDR / Wazuh Host Agent Telemetry |
| `SEBI-PROT-08` | **Part 3, Cl. 6.8** | Encryption of Sensitive Financial & Personal Data at Rest and Transit | Protect | [Mapped] | `CTRL-ENC-01` (Database Transparent Data Encryption (TDE) & Key Management (HSM)) | Database TDE / KMS HSM Key Rotation Audit Logs |
| `SEBI-PROT-09` | **Part 3, Cl. 6.9** | Data Loss Prevention (DLP) across Endpoints, Network & Egress | Protect | [Mapped] | `CTRL-DLP-01` (Enterprise Data Loss Prevention (DLP) across Endpoint, Network & Cloud Mail) | Enterprise DLP Agent Policy Block Records |
| `SEBI-PROT-10` | **Part 3, Cl. 6.10** | Hardening Baselines & CIS Benchmark Configuration Auditing | Protect | [Mapped] | `CTRL-HARD-01` (Automated CIS Benchmark Configuration Auditing & Host Hardening) | Wazuh SCA (Security Configuration Assessment) Telemetry |
| `SEBI-PROT-11` | **Part 3, Cl. 6.11** | Employee Cybersecurity Awareness & Phishing Simulation Drills | Protect | [Unmapped] | *None (Out of Scope)* | *Human resource training & operational awareness activity* |
| `SEBI-PROT-12` | **Part 3, Cl. 6.12** | Physical Security of Data Centers & Critical Facilities | Protect | [Unmapped] | *None (Out of Scope)* | *Physical facility access control (CCTV, biometric turnstiles)* |
| `SEBI-DET-01` | **Part 4, Cl. 7.1** | Centralized 24x7 Security Operations Centre (SOC) & SIEM | Detect | [Mapped] | `CTRL-SIEM-01` (Centralized SIEM + 24/7 Threat Hunting & Automated Playbook Response (SOAR)) | Centralized Wazuh/ELK SIEM Event Ingestion Stream |
| `SEBI-DET-02` | **Part 4, Cl. 7.2** | Continuous Behavioral Anomaly Detection & Threat Hunting | Detect | [Mapped] | `CTRL-ANOM-01` (Behavioral Anomaly & Threat Hunting Engine (Isolation Forest SIEM Analysis)) | CRISP Isolation Forest Anomaly Engine & Threat Intelligence |
| `SEBI-DET-03` | **Part 4, Cl. 7.3** | Statutory 6-Hour Incident Notification Capability | Detect | [Mapped] | `CTRL-SIEM-01` (Centralized SIEM + 24/7 Threat Hunting & Automated Playbook Response (SOAR)) | SEBI CSCRF 6-Hour Incident Triage Readiness Metric |
| `SEBI-RESP-01` | **Part 5, Cl. 8.1** | Incident Response Plan & CERT-In Empaneled Retainer SLA | Respond | [Mapped] | `CTRL-IR-01` (CERT-In Empaneled Incident Response Retainer & Cyber Crisis Simulation Drills) | CERT-In Retainer SLA Agreement & Incident Playbook |
| `SEBI-RESP-02` | **Part 5, Cl. 8.2** | Regulatory Reporting & Forensic Triage Execution | Respond | [Mapped] | `CTRL-IR-01` (CERT-In Empaneled Incident Response Retainer & Cyber Crisis Simulation Drills) | Forensic Readiness Checklist & Regulatory Incident Logging |
| `SEBI-REC-01` | **Part 5, Cl. 9.1** | Immutable & Air-Gapped Data Backup Infrastructure | Recover | [Mapped] | `CTRL-BKP-01` (Air-Gapped Immutable Backups & Automated Disaster Recovery Sandbox) | WORM / S3 Object Lock Immutable Backup Telemetry |
| `SEBI-REC-02` | **Part 5, Cl. 9.2** | 4-Hour Recovery Time Objective (RTO) Restoration Drills | Recover | [Mapped] | `CTRL-BKP-01` (Air-Gapped Immutable Backups & Automated Disaster Recovery Sandbox) | Disaster Recovery Drill Evidence & RTO Attestation |
| `SEBI-TPRM-01` | **Part 6, Cl. 10.1** | Third-Party Vendor Risk Assessment & API Sandboxing | TPRM | [Mapped] | `CTRL-TPRM-01` (Third-Party Cyber Supply Chain Risk Assessment & Continuous Telemetry Verification) | Vendor Onboarding Wizard & Telemetry Configuration Store |
| `SEBI-AUD-01` | **Part 7, Cl. 11.1** | Periodic VAPT & Independent Third-Party Cyber Audit | Assurance | [Mapped] | `CTRL-VAPT-01` (Mandatory External VAPT & Red-Teaming Exercises (CERT-In Empaneled)) | Independent CERT-In VAPT Audit Report & Attestation |

---

## RBI Cyber Security Framework (80.0% Mapped)

- **Citation**: RBI Circular RBI/2015-16/418 & Master Directions on IT Governance
- **Description**: Reserve Bank of India Cyber Security Framework for Banks and NBFCs
- **Scope**: **16** mapped controls / **20** total requirements (**4** unmapped)

| Requirement ID | Framework Clause | Requirement Title | Domain | Mapping Status | CRISP Control ID | Audit Evidence / Telemetry Source |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| `RBI-CSF-01` | **Annex 1, Cl. 1** | Inventory Management of Business IT Assets & Classifications | Inventory | [Mapped] | `CTRL-HARD-01` (Automated CIS Benchmark Configuration Auditing & Host Hardening) | CRISP Asset Schema & Network Telemetry Verification |
| `RBI-CSF-02` | **Annex 1, Cl. 2** | Preventing Unauthorized Software & Application Whitelisting | Endpoint | [Mapped] | `CTRL-EDR-01` (Next-Gen Endpoint Detection & Response (EDR) + Managed SOC (Wazuh/MDR)) | Microsoft Defender Application Control / Wazuh Syscheck |
| `RBI-CSF-03` | **Annex 1, Cl. 3** | Physical and Environmental Security Controls | Physical | [Unmapped] | *None (Out of Scope)* | *Physical premises protection (UPS, fire suppression, biometric gates)* |
| `RBI-CSF-04` | **Annex 1, Cl. 4** | Network Management, Security Zoning & Core Switch Isolation | Network | [Mapped] | `CTRL-SEG-01` (Zero Trust Micro-Segmentation (Payment Core & DB Isolation)) | Core Banking Network Micro-Segmentation Policies |
| `RBI-CSF-05` | **Annex 1, Cl. 5** | Secure Configuration & System Hardening Standards | Configuration | [Mapped] | `CTRL-HARD-01` (Automated CIS Benchmark Configuration Auditing & Host Hardening) | CIS Benchmark Hardening Audit Logs |
| `RBI-CSF-06` | **Annex 1, Cl. 6** | Anti-Virus & Automated Patch Management for Known Vulnerabilities | Vulnerability | [Mapped] | `CTRL-PATCH-01` (Automated Vulnerability Management & Patch Deployment Pipeline (SLA: 7 days for KEV)) | Vulnerability Scanner Telemetry & Patch Verification |
| `RBI-CSF-07` | **Annex 1, Cl. 7.1** | Privileged Access Management (PAM) for Elevated Accounts | Access | [Mapped] | `CTRL-PAM-01` (Privileged Access Management (PAM) Vault with Just-in-Time Session Recording) | PAM Session Vault Audit Telemetry |
| `RBI-CSF-08` | **Annex 1, Cl. 7.2** | Multi-Factor Authentication for Remote & Privileged Access | Access | [Mapped] | `CTRL-MFA-01` (Privileged Access Multi-Factor Authentication (FIDO2 / Hardware Token)) | FIDO2 / Hardware Token Authentication Records |
| `RBI-CSF-09` | **Annex 1, Cl. 7.3** | Removable Media Usage Restrictions & Port Blocking | Access | [Unmapped] | *None (Out of Scope)* | *Operational physical endpoint policy for removable USB drives* |
| `RBI-CSF-10` | **Annex 1, Cl. 8.1** | Protection of Customer Financial Data (Encryption at Rest & Transit) | Data | [Mapped] | `CTRL-ENC-01` (Database Transparent Data Encryption (TDE) & Key Management (HSM)) | Database TDE & HSM Encryption Key Attestation |
| `RBI-CSF-11` | **Annex 1, Cl. 8.2** | Data Loss Prevention (DLP) across Internet Banking Systems | Data | [Mapped] | `CTRL-DLP-01` (Enterprise Data Loss Prevention (DLP) across Endpoint, Network & Cloud Mail) | Endpoint & Network DLP Enforcement Logs |
| `RBI-CSF-12` | **Annex 1, Cl. 9** | Boundary Defense & Web Application Firewall for Internet Banking | Perimeter | [Mapped] | `CTRL-WAF-01` (Cloud-Native Web Application & API Protection (WAAP / WAF + DDoS Mitigation)) | WAF & DDoS Mitigation Appliance Logs |
| `RBI-CSF-13` | **Annex 1, Cl. 10** | Application Security Testing & Secure Open Banking APIs | Application | [Mapped] | `CTRL-API-01` (API Security Gateway with Machine Learning Behavioral Anomaly Detection) | API Security Gateway Inspection & DAST Telemetry |
| `RBI-CSF-14` | **Annex 1, Cl. 11** | Immutable Backups & Periodic Restoration Verification | Resilience | [Mapped] | `CTRL-BKP-01` (Air-Gapped Immutable Backups & Automated Disaster Recovery Sandbox) | Automated Immutable Backup & Restoration Check |
| `RBI-CSF-15` | **Annex 1, Cl. 12** | Security Operations Centre (SOC) 24x7 Continuous Monitoring | Operations | [Mapped] | `CTRL-SIEM-01` (Centralized SIEM + 24/7 Threat Hunting & Automated Playbook Response (SOAR)) | Wazuh SIEM Continuous Alert Monitoring |
| `RBI-CSF-16` | **Annex 1, Cl. 13** | Incident Management, Forensics & Cyber Crisis Management (CCMP) | Response | [Mapped] | `CTRL-IR-01` (CERT-In Empaneled Incident Response Retainer & Cyber Crisis Simulation Drills) | CCMP Playbook & CERT-In Reporting Channel |
| `RBI-CSF-17` | **Annex 1, Cl. 14** | Periodic VAPT & Red-Teaming Exercises by Empaneled Auditors | Assurance | [Mapped] | `CTRL-VAPT-01` (Mandatory External VAPT & Red-Teaming Exercises (CERT-In Empaneled)) | External Red Team Assessment & Remediation Report |
| `RBI-CSF-18` | **Annex 1, Cl. 15** | Vendor / Third-Party Cyber Risk Management & Due Diligence | TPRM | [Mapped] | `CTRL-TPRM-01` (Third-Party Cyber Supply Chain Risk Assessment & Continuous Telemetry Verification) | CRISP Vendor Management & Questionnaire Attestation |
| `RBI-CSF-19` | **Annex 1, Cl. 16** | Cybersecurity Training & Awareness for Bank Employees | Training | [Unmapped] | *None (Out of Scope)* | *Internal HR employee training curriculum and records* |
| `RBI-CSF-20` | **Annex 1, Cl. 17** | Customer Cybersecurity Education & Awareness Campaigns | Outreach | [Unmapped] | *None (Out of Scope)* | *Public outreach and customer education initiatives* |

---

## NIST CSF 2.0 (84.2% Mapped)

- **Citation**: NIST CSWP 29 (Feb 2024)
- **Description**: National Institute of Standards & Technology Cybersecurity Framework 2.0
- **Scope**: **16** mapped controls / **19** total requirements (**3** unmapped)

| Requirement ID | Framework Clause | Requirement Title | Domain | Mapping Status | CRISP Control ID | Audit Evidence / Telemetry Source |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| `NIST-GV-01` | **GV.OC-01** | Organizational Mission & Risk Context | Govern | [Unmapped] | *None (Out of Scope)* | *Enterprise governance & organizational mission documentation* |
| `NIST-GV-02` | **GV.RR-01** | Cybersecurity Roles and Responsibilities | Govern | [Unmapped] | *None (Out of Scope)* | *HR roles, responsibilities, and accountability assignments* |
| `NIST-GV-03` | **GV.SC-04** | Cybersecurity Supply Chain Risk Management | Govern | [Mapped] | `CTRL-TPRM-01` (Third-Party Cyber Supply Chain Risk Assessment & Continuous Telemetry Verification) | Vendor Security Assessment Telemetry |
| `NIST-ID-01` | **ID.AM-01** | Physical and Software Asset Inventories | Identify | [Mapped] | `CTRL-HARD-01` (Automated CIS Benchmark Configuration Auditing & Host Hardening) | CRISP Asset Schema & Network Telemetry Verification |
| `NIST-ID-02` | **ID.RA-01** | Vulnerability Identification & Risk Assessment | Identify | [Mapped] | `CTRL-PATCH-01` (Automated Vulnerability Management & Patch Deployment Pipeline (SLA: 7 days for KEV)) | OpenVAS / Nessus Scans & FIRST EPSS Intelligence |
| `NIST-PR-01` | **PR.AA-01** | Identity Management, Credentials & Access Authentication | Protect | [Mapped] | `CTRL-MFA-01` (Privileged Access Multi-Factor Authentication (FIDO2 / Hardware Token)) | Keycloak IAM / FIDO2 Authentication Telemetry |
| `NIST-PR-02` | **PR.AA-05** | Privileged Access Management & Credential Vaulting | Protect | [Mapped] | `CTRL-PAM-01` (Privileged Access Management (PAM) Vault with Just-in-Time Session Recording) | PAM Bastion Vault Telemetry |
| `NIST-PR-03` | **PR.IR-01** | Network Micro-Segmentation & Boundary Isolation | Protect | [Mapped] | `CTRL-SEG-01` (Zero Trust Micro-Segmentation (Payment Core & DB Isolation)) | Network Security Group & Routing Ingress Telemetry |
| `NIST-PR-04` | **PR.IR-02** | Web Application Perimeter Defense (WAF) | Protect | [Mapped] | `CTRL-WAF-01` (Cloud-Native Web Application & API Protection (WAAP / WAF + DDoS Mitigation)) | Cloud WAF Ingress Telemetry |
| `NIST-PR-05` | **PR.DS-01** | Confidentiality & Integrity of Data-at-Rest (Encryption) | Protect | [Mapped] | `CTRL-ENC-01` (Database Transparent Data Encryption (TDE) & Key Management (HSM)) | Database Transparent Data Encryption & KMS Logs |
| `NIST-PR-06` | **PR.DS-10** | Protection Against Unauthorized Data Exfiltration (DLP) | Protect | [Mapped] | `CTRL-DLP-01` (Enterprise Data Loss Prevention (DLP) across Endpoint, Network & Cloud Mail) | Enterprise DLP Endpoint & Network Enforcement |
| `NIST-PR-07` | **PR.PS-01** | Configuration Baselines & System Hardening | Protect | [Mapped] | `CTRL-HARD-01` (Automated CIS Benchmark Configuration Auditing & Host Hardening) | CIS Benchmark Configuration Auditing |
| `NIST-PR-08` | **PR.PS-06** | Secure Software Development & API Protection | Protect | [Mapped] | `CTRL-API-01` (API Security Gateway with Machine Learning Behavioral Anomaly Detection) | API Security Gateway Telemetry |
| `NIST-PR-09` | **PR.AT-01** | Workforce Cybersecurity Awareness & Skills Training | Protect | [Unmapped] | *None (Out of Scope)* | *Personnel security awareness and phishing training tracking* |
| `NIST-DE-01` | **DE.CM-01** | Continuous Network & Asset Log Centralization | Detect | [Mapped] | `CTRL-SIEM-01` (Centralized SIEM + 24/7 Threat Hunting & Automated Playbook Response (SOAR)) | Wazuh SIEM Central Log Aggregator |
| `NIST-DE-02` | **DE.CM-06** | Endpoint Malicious Code & Host EDR Monitoring | Detect | [Mapped] | `CTRL-EDR-01` (Next-Gen Endpoint Detection & Response (EDR) + Managed SOC (Wazuh/MDR)) | Microsoft Defender for Endpoint Telemetry |
| `NIST-DE-03` | **DE.AE-02** | Behavioral Anomaly Analysis & Threat Intelligence Correlation | Detect | [Mapped] | `CTRL-ANOM-01` (Behavioral Anomaly & Threat Hunting Engine (Isolation Forest SIEM Analysis)) | Isolation Forest Anomaly Engine & Threat Feeds |
| `NIST-RS-01` | **RS.MA-01** | Incident Management Execution & Stakeholder Coordination | Respond | [Mapped] | `CTRL-IR-01` (CERT-In Empaneled Incident Response Retainer & Cyber Crisis Simulation Drills) | CERT-In Retainer & Incident Playbook |
| `NIST-RC-01` | **RC.RP-01** | Recovery Plan Execution & Immutable Backup Restoration | Recover | [Mapped] | `CTRL-BKP-01` (Air-Gapped Immutable Backups & Automated Disaster Recovery Sandbox) | Immutable Backup Validation & DR Sandbox Drills |

---

## ISO/IEC 27001:2022 (82.6% Mapped)

- **Citation**: ISO/IEC 27001:2022 Information security, cybersecurity and privacy protection
- **Description**: Information Security Management System - Annex A Controls
- **Scope**: **19** mapped controls / **23** total requirements (**4** unmapped)

| Requirement ID | Framework Clause | Requirement Title | Domain | Mapping Status | CRISP Control ID | Audit Evidence / Telemetry Source |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| `ISO-A.5.15` | **A.5.15** | Access Control Policies & Privileged Authorization | Organizational | [Mapped] | `CTRL-PAM-01` (Privileged Access Management (PAM) Vault with Just-in-Time Session Recording) | PAM Session Auditing Telemetry |
| `ISO-A.5.19` | **A.5.19** | Information Security in Supplier Relationships | Organizational | [Mapped] | `CTRL-TPRM-01` (Third-Party Cyber Supply Chain Risk Assessment & Continuous Telemetry Verification) | Third-Party Risk Assessment Telemetry |
| `ISO-A.5.24` | **A.5.24** | Information Security Incident Management Planning | Organizational | [Mapped] | `CTRL-IR-01` (CERT-In Empaneled Incident Response Retainer & Cyber Crisis Simulation Drills) | Incident Response Retainer & Playbook |
| `ISO-A.5.30` | **A.5.30** | ICT Readiness for Business Continuity | Organizational | [Mapped] | `CTRL-BKP-01` (Air-Gapped Immutable Backups & Automated Disaster Recovery Sandbox) | Disaster Recovery Drill Evidence |
| `ISO-A.6.1` | **A.6.1** | Candidate Screening & Employment Background Checks | People | [Unmapped] | *None (Out of Scope)* | *Human resources pre-employment verification procedures* |
| `ISO-A.6.3` | **A.6.3** | Information Security Awareness, Education and Training | People | [Unmapped] | *None (Out of Scope)* | *Annual corporate security training tracking* |
| `ISO-A.7.1` | **A.7.1** | Physical Security Perimeters & Data Center Barriers | Physical | [Unmapped] | *None (Out of Scope)* | *Physical perimeter security (fencing, access cards, guards)* |
| `ISO-A.7.4` | **A.7.4** | Physical Security Monitoring (CCTV & Environmental Alarms) | Physical | [Unmapped] | *None (Out of Scope)* | *Surveillance system video retention and power/cooling telemetry* |
| `ISO-A.8.1` | **A.8.1** | User Endpoint Device Security & Management | Technological | [Mapped] | `CTRL-EDR-01` (Next-Gen Endpoint Detection & Response (EDR) + Managed SOC (Wazuh/MDR)) | Microsoft Defender EDR Telemetry |
| `ISO-A.8.2` | **A.8.2** | Privileged Access Rights & Vault Management | Technological | [Mapped] | `CTRL-PAM-01` (Privileged Access Management (PAM) Vault with Just-in-Time Session Recording) | PAM Bastion Vault Access Logs |
| `ISO-A.8.5` | **A.8.5** | Secure Authentication (Multi-Factor Authentication) | Technological | [Mapped] | `CTRL-MFA-01` (Privileged Access Multi-Factor Authentication (FIDO2 / Hardware Token)) | Keycloak IAM FIDO2 Records |
| `ISO-A.8.7` | **A.8.7** | Protection Against Malware (Anti-Malware & EDR) | Technological | [Mapped] | `CTRL-EDR-01` (Next-Gen Endpoint Detection & Response (EDR) + Managed SOC (Wazuh/MDR)) | EDR Active Malware Detection Telemetry |
| `ISO-A.8.8` | **A.8.8** | Management of Technical Vulnerabilities (Patching) | Technological | [Mapped] | `CTRL-PATCH-01` (Automated Vulnerability Management & Patch Deployment Pipeline (SLA: 7 days for KEV)) | OpenVAS / Nessus Vulnerability Feeds |
| `ISO-A.8.9` | **A.8.9** | Configuration Management & Systems Hardening | Technological | [Mapped] | `CTRL-HARD-01` (Automated CIS Benchmark Configuration Auditing & Host Hardening) | Wazuh CIS Benchmark Assessments |
| `ISO-A.8.12` | **A.8.12** | Data Leakage Prevention (DLP) | Technological | [Mapped] | `CTRL-DLP-01` (Enterprise Data Loss Prevention (DLP) across Endpoint, Network & Cloud Mail) | Enterprise DLP Telemetry |
| `ISO-A.8.13` | **A.8.13** | Information Backup & Immutable Retention | Technological | [Mapped] | `CTRL-BKP-01` (Air-Gapped Immutable Backups & Automated Disaster Recovery Sandbox) | Immutable Backup Validation Logs |
| `ISO-A.8.15` | **A.8.15** | Logging & Audit Trail Management | Technological | [Mapped] | `CTRL-SIEM-01` (Centralized SIEM + 24/7 Threat Hunting & Automated Playbook Response (SOAR)) | Wazuh SIEM Central Log Retention |
| `ISO-A.8.16` | **A.8.16** | Monitoring Activities & Anomaly Detection | Technological | [Mapped] | `CTRL-ANOM-01` (Behavioral Anomaly & Threat Hunting Engine (Isolation Forest SIEM Analysis)) | Isolation Forest Anomaly Telemetry |
| `ISO-A.8.20` | **A.8.20** | Network Security & Web Application Filtering | Technological | [Mapped] | `CTRL-WAF-01` (Cloud-Native Web Application & API Protection (WAAP / WAF + DDoS Mitigation)) | WAF & DDoS Mitigation Appliance Logs |
| `ISO-A.8.24` | **A.8.24** | Use of Cryptography & Key Management | Technological | [Mapped] | `CTRL-ENC-01` (Database Transparent Data Encryption (TDE) & Key Management (HSM)) | Database TDE & KMS HSM Telemetry |
| `ISO-A.8.26` | **A.8.26** | Application Security Requirements & Secure APIs | Technological | [Mapped] | `CTRL-API-01` (API Security Gateway with Machine Learning Behavioral Anomaly Detection) | API Security Gateway Inspection |
| `ISO-A.8.31` | **A.8.31** | Separation of Development, Test and Production Environments | Technological | [Mapped] | `CTRL-SEG-01` (Zero Trust Micro-Segmentation (Payment Core & DB Isolation)) | VPC & Micro-Segmentation Firewall Ingress Logs |
| `ISO-A.8.34` | **A.8.34** | Independent Technical Security Assessment (VAPT) | Technological | [Mapped] | `CTRL-VAPT-01` (Mandatory External VAPT & Red-Teaming Exercises (CERT-In Empaneled)) | Periodic External Penetration Testing Reports |

---

## CIS Controls v8 (94.4% Mapped)

- **Citation**: CIS Controls v8 (Center for Internet Security 2021)
- **Description**: Center for Internet Security Critical Security Controls Version 8
- **Scope**: **17** mapped controls / **18** total requirements (**1** unmapped)

| Requirement ID | Framework Clause | Requirement Title | Domain | Mapping Status | CRISP Control ID | Audit Evidence / Telemetry Source |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| `CIS-01` | **CIS Control 1** | Inventory and Control of Enterprise Assets | Hygiene | [Mapped] | `CTRL-HARD-01` (Automated CIS Benchmark Configuration Auditing & Host Hardening) | CRISP Asset Schema & Network Telemetry Verification |
| `CIS-02` | **CIS Control 2** | Inventory and Control of Software Assets | Hygiene | [Mapped] | `CTRL-PATCH-01` (Automated Vulnerability Management & Patch Deployment Pipeline (SLA: 7 days for KEV)) | OpenVAS / Nessus Vulnerability Scanning Feeds |
| `CIS-03` | **CIS Control 3** | Data Protection (Encryption & Data Loss Prevention) | Data | [Mapped] | `CTRL-ENC-01` (Database Transparent Data Encryption (TDE) & Key Management (HSM)) | Database TDE & Enterprise DLP Telemetry |
| `CIS-04` | **CIS Control 4** | Secure Configuration of Enterprise Assets and Software | Configuration | [Mapped] | `CTRL-HARD-01` (Automated CIS Benchmark Configuration Auditing & Host Hardening) | CIS Benchmark Configuration Auditing |
| `CIS-05` | **CIS Control 5** | Account Management & Privileged Credential Control | Access | [Mapped] | `CTRL-PAM-01` (Privileged Access Management (PAM) Vault with Just-in-Time Session Recording) | PAM Session Vault Audit Telemetry |
| `CIS-06` | **CIS Control 6** | Access Control Management (Multi-Factor Authentication) | Access | [Mapped] | `CTRL-MFA-01` (Privileged Access Multi-Factor Authentication (FIDO2 / Hardware Token)) | Keycloak IAM FIDO2 Records |
| `CIS-07` | **CIS Control 7** | Continuous Vulnerability Management | Vulnerability | [Mapped] | `CTRL-PATCH-01` (Automated Vulnerability Management & Patch Deployment Pipeline (SLA: 7 days for KEV)) | OpenVAS Scan Ingestion & Threat Feeds |
| `CIS-08` | **CIS Control 8** | Audit Log Management & Centralized SIEM | Operations | [Mapped] | `CTRL-SIEM-01` (Centralized SIEM + 24/7 Threat Hunting & Automated Playbook Response (SOAR)) | Wazuh SIEM Central Log Retention |
| `CIS-09` | **CIS Control 9** | Email and Web Browser Protections (WAF & Egress Defense) | Perimeter | [Mapped] | `CTRL-WAF-01` (Cloud-Native Web Application & API Protection (WAAP / WAF + DDoS Mitigation)) | Cloud WAF Ingress Telemetry |
| `CIS-10` | **CIS Control 10** | Malware Defenses (Endpoint Detection & Response) | Endpoint | [Mapped] | `CTRL-EDR-01` (Next-Gen Endpoint Detection & Response (EDR) + Managed SOC (Wazuh/MDR)) | Microsoft Defender EDR Telemetry |
| `CIS-11` | **CIS Control 11** | Data Recovery (Air-Gapped Immutable Backups) | Resilience | [Mapped] | `CTRL-BKP-01` (Air-Gapped Immutable Backups & Automated Disaster Recovery Sandbox) | Immutable Backup Validation & DR Sandbox Drills |
| `CIS-12` | **CIS Control 12** | Network Infrastructure Management (Micro-Segmentation) | Network | [Mapped] | `CTRL-SEG-01` (Zero Trust Micro-Segmentation (Payment Core & DB Isolation)) | VPC & Micro-Segmentation Firewall Ingress Logs |
| `CIS-13` | **CIS Control 13** | Network Monitoring and Defense (Anomaly Detection) | Operations | [Mapped] | `CTRL-ANOM-01` (Behavioral Anomaly & Threat Hunting Engine (Isolation Forest SIEM Analysis)) | Isolation Forest Anomaly Telemetry |
| `CIS-14` | **CIS Control 14** | Security Awareness and Skills Training | Training | [Unmapped] | *None (Out of Scope)* | *Personnel training curriculum and social engineering testing* |
| `CIS-15` | **CIS Control 15** | Service Provider Management (Third-Party Risk) | TPRM | [Mapped] | `CTRL-TPRM-01` (Third-Party Cyber Supply Chain Risk Assessment & Continuous Telemetry Verification) | Third-Party Vendor Risk Assessment Telemetry |
| `CIS-16` | **CIS Control 16** | Application Software Security (Secure APIs) | Application | [Mapped] | `CTRL-API-01` (API Security Gateway with Machine Learning Behavioral Anomaly Detection) | API Security Gateway Inspection |
| `CIS-17` | **CIS Control 17** | Incident Response Management | Response | [Mapped] | `CTRL-IR-01` (CERT-In Empaneled Incident Response Retainer & Cyber Crisis Simulation Drills) | Incident Response Retainer & Playbook |
| `CIS-18` | **CIS Control 18** | Penetration Testing (Independent VAPT) | Assurance | [Mapped] | `CTRL-VAPT-01` (Mandatory External VAPT & Red-Teaming Exercises (CERT-In Empaneled)) | Periodic External Penetration Testing Reports |

---

## Framework-ID Alias Normalization & Loud Failure Philosophy

CRISP enforces strict alias normalization through `normalize_framework_id()`. When an unrecognized framework identifier is requested, the system fails **loudly** with HTTP 400 and an explicit list of accepted identifiers.

### Normalization Verification Table
| Input Alias | Canonical Resolved ID | Normalization Result |
| :--- | :--- | :--- |
| `sebi` | `sebi` | Success (Maps to `sebi`) |
| `sebi_cscrf` | `sebi` | Success (Maps to `sebi`) |
| `sebicscrf` | `sebi` | Success (Maps to `sebi`) |
| `rbi` | `rbi` | Success (Maps to `rbi`) |
| `rbi_csf` | `rbi` | Success (Maps to `rbi`) |
| `nist` | `nist` | Success (Maps to `nist`) |
| `nist_csf` | `nist` | Success (Maps to `nist`) |
| `iso` | `iso` | Success (Maps to `iso`) |
| `iso_27001` | `iso` | Success (Maps to `iso`) |
| `cis` | `cis` | Success (Maps to `cis`) |
| `cis_v8` | `cis` | Success (Maps to `cis`) |

### Loud Failure Verification Log
- `Expected loud failure for 'unknown_fw': Unknown framework 'unknown_fw'. Valid IDs: cis, dpdp, iso, nist, rbi, sebi. Also accepted aliases: cis controls, cis_v8, cisv8, dpdp_act, iso27001, iso/iec 27001, iso_27001, nist_csf, nistcsf, rbi_csf, sebi_cscrf, sebicscrf`
- `Expected loud failure for 'pci_dss_99': Unknown framework 'pci_dss_99'. Valid IDs: cis, dpdp, iso, nist, rbi, sebi. Also accepted aliases: cis controls, cis_v8, cisv8, dpdp_act, iso27001, iso/iec 27001, iso_27001, nist_csf, nistcsf, rbi_csf, sebi_cscrf, sebicscrf`
