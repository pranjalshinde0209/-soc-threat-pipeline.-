# Enterprise Threat Detection & Incident Triage Pipeline

![Cybersecurity](https://img.shields.io/badge/Domain-Defensive%20Security%20%2F%20SOC-blue)
![Language](https://img.shields.io/badge/Language-Python%203-brightgreen)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-orange)

An end-to-end security operations lab implementing log aggregation, custom threat detection mapped to the MITRE ATT&CK framework, and automated incident triage using Python and Threat Intelligence APIs.

---

## Architecture Overview

```text
[Simulated Endpoints] 
    (Windows Sysmon / Linux Auditd)
               │
               ▼
[Wazuh SIEM / Log Engine] ────> Custom Detection Rules (MITRE ATT&CK Mapped)
               │
               ▼
   [Alert JSON Forwarding]
               │
               ▼
   [Python Triage Engine]  ────> AbuseIPDB & VirusTotal APIs
               │
               ▼
   [Automated Markdown Reports & Remediation Guidance]
