import os
import json
import requests
from datetime import datetime

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

def check_ip_reputation(ip_address: str) -> dict:
    if ip_address.startswith(("10.", "192.168.", "172.16.", "127.")):
        return {"ip": ip_address, "reputation": "Private IP (Internal)", "abuse_score": 0}

    if not ABUSEIPDB_KEY:
        return {"ip": ip_address, "reputation": "API key missing", "abuse_score": 0}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_KEY}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip": ip_address,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
            }
    except requests.RequestException as err:
        return {"ip": ip_address, "error": str(err)}

    return {"ip": ip_address, "reputation": "Query failed", "abuse_score": 0}

def check_file_hash(sha256_hash: str) -> dict:
    if not VIRUSTOTAL_KEY or not sha256_hash:
        return {"hash": sha256_hash, "reputation": "No check performed", "malicious_votes": 0}

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "hash": sha256_hash,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
            }
    except requests.RequestException as err:
        return {"hash": sha256_hash, "error": str(err)}

    return {"hash": sha256_hash, "reputation": "Not found in VT database", "malicious_votes": 0}

def run_triage(alert_file_path: str):
    if not os.path.exists(alert_file_path):
        print(f"[!] Alert file {alert_file_path} not found.")
        return

    with open(alert_file_path, "r", encoding="utf-8") as file:
        alert = json.load(file)

    src_ip = alert.get("src_ip", "")
    file_hash = alert.get("file_hash", "")
    rule_title = alert.get("rule_description", "Unknown Security Event")
    mitre_technique = alert.get("mitre_id", "N/A")

    ip_intel = check_ip_reputation(src_ip) if src_ip else {}
    hash_intel = check_file_hash(file_hash) if file_hash else {}

    score = ip_intel.get("abuse_score", 0)
    vt_malicious = hash_intel.get("malicious", 0)

    if score > 50 or vt_malicious > 5:
        verdict = "CRITICAL / TRUE POSITIVE"
    elif score > 20 or vt_malicious > 0:
        verdict = "SUSPICIOUS / INVESTIGATION REQUIRED"
    else:
        verdict = "LOW / POTENTIAL BENIGN ACTIVITY"

    report = f"""# Incident Triage Summary
**Date/Time:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Alert:** {rule_title}  
**MITRE ATT&CK Mapping:** {mitre_technique}  
**Automated Triage Verdict:** `{verdict}`  

---

### Telemetry Details
* **Source Host / IP:** `{src_ip}`
* **Target Host:** `{alert.get('dest_host', 'N/A')}`
* **User Involved:** `{alert.get('user', 'N/A')}`
* **Executable Path:** `{alert.get('process_path', 'N/A')}`

### Threat Intelligence Enrichment
* **AbuseIPDB Confidence Score:** {ip_intel.get('abuse_score', 'N/A')}%
* **AbuseIPDB Total Reports:** {ip_intel.get('totalReports', ip_intel.get('total_reports', 0))}
* **VirusTotal Detections:** {hash_intel.get('malicious', 0)} engines flagged malicious

---
### Recommended Next Actions
1. Confirm host isolation status via EDR.
2. Review process tree logs around the execution timestamp.
3. Add source IP to firewall drop list if confirmed external adversary.
"""

    output_filename = f"incident_triage_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
    with open(output_filename, "w", encoding="utf-8") as out:
        out.write(report)

    print(f"[+] Triage completed. Report generated: {output_filename}")

if __name__ == "__main__":
    mock_alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "rule_description": "Suspicious PowerShell Download Cradle Observed",
        "mitre_id": "T1059.001 - Command and Scripting Interpreter",
        "src_ip": "185.220.101.5",
        "dest_host": "SEC-WS-004",
        "user": "corp\\jdoe",
        "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "file_hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    }

    test_file = "sample_alert.json"
    with open(test_file, "w", encoding="utf-8") as f:
        json.dump(mock_alert, f, indent=2)

    run_triage(test_file)
    if os.path.exists(test_file):
        os.remove(test_file)
