# =============================================================
# CYBER CRIME SCENE ANALYZER
# Takes raw incident data and builds a detective-style timeline
# =============================================================

import re
from datetime import datetime

# Evidence types with their detection patterns
EVIDENCE_TYPES = [
    {
        "type": "phishing_email",
        "icon": "📧",
        "label": "Phishing Email",
        "color": "#ef4444",
        "patterns": [
            r"phish|spam|malicious.*email|suspicious.*mail|click.*link|urgent.*action",
            r"from:.*\.(ru|cn|tk|ml|ga|cf)|subject:.*verify|subject:.*account",
            r"attachment|\.exe|\.zip|\.docm|macro"
        ],
        "questions": [
            "Who sent the email?",
            "What was the subject line?",
            "Were there attachments?",
            "Did the user click any links?"
        ]
    },
    {
        "type": "malicious_url",
        "icon": "🌐",
        "label": "Malicious URL",
        "color": "#f97316",
        "patterns": [
            r"http[s]?://.*\.(tk|ml|ga|cf|ru|cn|xyz|top)",
            r"paypa[l1]|amaz[o0]n|g[o0]{2}gle|micr[o0]s[o0]ft",
            r"phish|malware|c2|command.*control|\.onion"
        ],
        "questions": [
            "What is the full URL?",
            "Was it clicked by a user?",
            "What domain is it hosted on?",
            "Is it still active?"
        ]
    },
    {
        "type": "suspicious_login",
        "icon": "👤",
        "label": "Suspicious Login",
        "color": "#eab308",
        "patterns": [
            r"failed.*login|invalid.*password|authentication.*fail",
            r"login.*unusual.*location|impossible.*travel",
            r"brute.*force|credential.*stuff|multiple.*attempt"
        ],
        "questions": [
            "Which account was targeted?",
            "Where did the login originate?",
            "Was the login successful?",
            "Is this a known user location?"
        ]
    },
    {
        "type": "malware_execution",
        "icon": "💻",
        "label": "Malware/PowerShell",
        "color": "#a855f7",
        "patterns": [
            r"powershell|cmd\.exe|wscript|cscript|mshta",
            r"\.exe|\.bat|\.vbs|\.ps1|\.dll",
            r"malware|trojan|ransomware|keylogger|backdoor|rootkit"
        ],
        "questions": [
            "What process was executed?",
            "Which user ran it?",
            "What system was affected?",
            "Are there child processes?"
        ]
    },
    {
        "type": "data_exfiltration",
        "icon": "📤",
        "label": "Data Exfiltration",
        "color": "#ec4899",
        "patterns": [
            r"large.*transfer|data.*leak|exfil|unusual.*upload",
            r"bytes.*sent|POST.*\d{6,}|ftp.*transfer",
            r"cloud.*upload|dropbox|mega\.nz|pastebin"
        ],
        "questions": [
            "How much data was transferred?",
            "Where was it sent?",
            "What type of data?",
            "Was encryption used?"
        ]
    },
    {
        "type": "lateral_movement",
        "icon": "↔️",
        "label": "Lateral Movement",
        "color": "#06b6d4",
        "patterns": [
            r"lateral.*movement|pivot|pass.*hash|mimikatz",
            r"psexec|wmi|smb|rdp.*internal|net.*use",
            r"new.*admin|privilege.*escalat|domain.*admin"
        ],
        "questions": [
            "Which systems were accessed?",
            "What credentials were used?",
            "What is the attack path?",
            "Which systems are at risk?"
        ]
    },
    {
        "type": "c2_communication",
        "icon": "📡",
        "label": "C2 Communication",
        "color": "#14b8a6",
        "patterns": [
            r"command.*control|c2|beaconing|callback",
            r":4444|:1337|:8080|:31337|irc\.",
            r"dns.*tunnel|covert.*channel|reverse.*shell"
        ],
        "questions": [
            "What IP/domain was contacted?",
            "What port was used?",
            "How frequent were the beacons?",
            "Was traffic encrypted?"
        ]
    },
    {
        "type": "network_scan",
        "icon": "🔭",
        "label": "Network Reconnaissance",
        "color": "#3b82f6",
        "patterns": [
            r"nmap|masscan|port.*scan|network.*sweep",
            r"syn.*flood|icmp.*sweep|ping.*sweep",
            r"enumerat|recon|discovery|fingerprint"
        ],
        "questions": [
            "What IP range was scanned?",
            "Which ports were probed?",
            "What was the scan speed?",
            "Was it internal or external?"
        ]
    }
]

def extract_iocs(text):
    """Extract IOCs from incident text"""
    iocs = {
        "ips": list(set(re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text))),
        "urls": list(set(re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text))),
        "hashes": list(set(re.findall(r'\b[a-fA-F0-9]{32,64}\b', text))),
        "emails": list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text))),
        "domains": list(set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)))
    }
    return iocs

def extract_timestamps(text):
    """Extract timestamps from incident text"""
    patterns = [
        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
        r'\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}',
        r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    ]
    timestamps = []
    for p in patterns:
        timestamps.extend(re.findall(p, text))
    return timestamps[:10]

def analyze_crime_scene(incident_text):
    """
    Main function — analyzes incident text and builds evidence cards
    """
    text_lower = incident_text.lower()
    evidence_cards = []
    
    for evidence in EVIDENCE_TYPES:
        matched = False
        match_count = 0
        
        for pattern in evidence["patterns"]:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                matched = True
                match_count += len(matches)
        
        if matched:
            evidence_cards.append({
                "type": evidence["type"],
                "icon": evidence["icon"],
                "label": evidence["label"],
                "color": evidence["color"],
                "occurrences": match_count,
                "questions": evidence["questions"],
                "severity": "Critical" if match_count > 3 else "High" if match_count > 1 else "Medium"
            })
    
    # Sort by severity and occurrence count
    severity_order = {"Critical": 0, "High": 1, "Medium": 2}
    evidence_cards.sort(key=lambda x: (severity_order[x["severity"]], -x["occurrences"]))
    
    # Extract IOCs
    iocs = extract_iocs(incident_text)
    timestamps = extract_timestamps(incident_text)
    
    # Determine case status
    critical_count = sum(1 for e in evidence_cards if e["severity"] == "Critical")
    
    if not evidence_cards:
        case_status = "INSUFFICIENT EVIDENCE"
        case_color = "#64748b"
        case_summary = "No clear attack indicators found. Gather more evidence."
    elif critical_count >= 2:
        case_status = "ACTIVE BREACH"
        case_color = "#ef4444"
        case_summary = f"Active attack in progress! {len(evidence_cards)} evidence types found. Immediate containment required."
    elif critical_count == 1:
        case_status = "UNDER INVESTIGATION"
        case_color = "#f97316"
        case_summary = f"Significant incident detected. {len(evidence_cards)} evidence types identified. Escalation recommended."
    elif len(evidence_cards) >= 2:
        case_status = "SOLVED ✔"
        case_color = "#22c55e"
        case_summary = f"Attack chain reconstructed. {len(evidence_cards)} evidence types identified. Containment actions defined."
    else:
        case_status = "MONITORING"
        case_color = "#eab308"
        case_summary = "Suspicious activity detected. Continue monitoring and gather more evidence."
    
    # Build attack timeline narrative
    timeline = []
    if any(e["type"] == "phishing_email" for e in evidence_cards):
        timeline.append("1. Initial Access via phishing email")
    if any(e["type"] == "malicious_url" for e in evidence_cards):
        timeline.append("2. User accessed malicious URL")
    if any(e["type"] == "malware_execution" for e in evidence_cards):
        timeline.append("3. Malware executed on endpoint")
    if any(e["type"] == "c2_communication" for e in evidence_cards):
        timeline.append("4. C2 communication established")
    if any(e["type"] == "suspicious_login" for e in evidence_cards):
        timeline.append("5. Credential theft / suspicious login")
    if any(e["type"] == "lateral_movement" for e in evidence_cards):
        timeline.append("6. Lateral movement across network")
    if any(e["type"] == "data_exfiltration" for e in evidence_cards):
        timeline.append("7. Data exfiltration attempted")
    
    return {
        "evidence_cards": evidence_cards,
        "iocs": iocs,
        "timestamps": timestamps,
        "case_status": case_status,
        "case_color": case_color,
        "case_summary": case_summary,
        "attack_timeline": timeline,
        "evidence_count": len(evidence_cards),
        "critical_count": critical_count
    }

if __name__ == '__main__':
    test = """
    User received phishing email from admin@paypa1-secure.tk with subject "Urgent: Verify Account"
    User clicked malicious URL http://paypa1-secure.tk/login
    Failed password attempts from 185.220.101.45
    PowerShell execution detected: powershell.exe -enc base64string
    Outbound connection to C2 server on port 4444
    Large data transfer: 500MB sent to 192.168.1.200
    Lateral movement detected via SMB to internal servers
    """
    result = analyze_crime_scene(test)
    print(f"Case Status: {result['case_status']}")
    print(f"Evidence Found: {result['evidence_count']} types")
    for e in result['evidence_cards']:
        print(f"  {e['icon']} {e['label']} ({e['severity']})")
    print(f"Timeline: {len(result['attack_timeline'])} steps")
