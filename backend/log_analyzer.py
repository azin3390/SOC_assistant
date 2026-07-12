# =============================================================
# LOG ANALYZER
# Regex-based attack pattern matching + ML anomaly detection
# (Isolation Forest) on per-IP behavioral features.
# =============================================================

import re
import pickle
import os
from log_features import parse_log_text, build_ip_features, features_to_vector

# Known attack patterns to detect in logs
ATTACK_PATTERNS = [
    {
        "name": "Brute Force Attack",
        "pattern": r"Failed password|authentication failure|Invalid user|failed login",
        "severity": "High",
        "description": "Multiple failed login attempts detected — possible brute force attack",
        "recommendation": "Block the source IP, enable rate limiting, enforce MFA"
    },
    {
        "name": "SQL Injection Attempt",
        "pattern": r"UNION SELECT|OR 1=1|DROP TABLE|INSERT INTO|--\s|/\*.*\*/|xp_cmdshell",
        "severity": "Critical",
        "description": "SQL injection strings detected in requests",
        "recommendation": "Check database for unauthorized access, review WAF rules, patch vulnerable endpoints"
    },
    {
        "name": "XSS Attempt",
        "pattern": r"<script|javascript:|onerror=|onload=|alert\(|document\.cookie",
        "severity": "High",
        "description": "Cross-site scripting attempt detected in request",
        "recommendation": "Sanitize all user inputs, implement Content Security Policy headers"
    },
    {
        "name": "Directory Traversal",
        "pattern": r"\.\./|\.\.\\|%2e%2e|etc/passwd|etc/shadow|win/system32",
        "severity": "Critical",
        "description": "Directory traversal attempt — attacker trying to access system files",
        "recommendation": "Validate and sanitize file path inputs, restrict file system access"
    },
    {
        "name": "Port Scan",
        "pattern": r"SYN_SENT|connection refused|ICMP|nmap|masscan",
        "severity": "Medium",
        "description": "Port scanning activity detected — attacker mapping your network",
        "recommendation": "Block scanning IP at firewall, enable IDS/IPS rules"
    },
    {
        "name": "Ransomware Activity",
        "pattern": r"\.encrypted|\.locked|\.ransom|DECRYPT|README_FOR_DECRYPT|port 445",
        "severity": "Critical",
        "description": "Ransomware indicators detected — immediate action required",
        "recommendation": "IMMEDIATELY isolate affected systems, do not pay ransom, restore from backups"
    },
    {
        "name": "Suspicious User Agent",
        "pattern": r"sqlmap|nikto|nessus|metasploit|burpsuite|havij|acunetix",
        "severity": "High",
        "description": "Known security scanner or attack tool detected",
        "recommendation": "Block the IP, review what endpoints were scanned"
    },
    {
        "name": "Command Injection",
        "pattern": r";\s*ls|;\s*cat|;\s*wget|;\s*curl|\|.*bash|\`.*\`|/bin/sh|/bin/bash",
        "severity": "Critical",
        "description": "Command injection attempt — attacker trying to run system commands",
        "recommendation": "Sanitize inputs immediately, check if any commands were executed"
    },
    {
        "name": "Suspicious Port Activity",
        "pattern": r":4444|:1337|:31337|:8080|:8888|:9999",
        "severity": "High",
        "description": "Connection to suspicious port — possible C2 communication or backdoor",
        "recommendation": "Block the port at firewall, investigate the process using the port"
    },
    {
        "name": "Data Exfiltration",
        "pattern": r"large.*transfer|bytes.*sent.*[0-9]{6,}|upload.*[0-9]{5,}|POST.*[0-9]{6,}",
        "severity": "High",
        "description": "Unusually large data transfer detected — possible data exfiltration",
        "recommendation": "Block outbound transfer, investigate what data was sent and to where"
    }
]

_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'anomaly_model.pkl')
_model = None

def _load_model():
    global _model
    if _model is None:
        with open(_MODEL_PATH, 'rb') as f:
            _model = pickle.load(f)
    return _model


def extract_ips_from_logs(log_text):
    """Extract all unique IPs from log text"""
    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log_text)
    return list(set(ips))

def count_occurrences(pattern, text):
    """Count how many times a pattern appears"""
    return len(re.findall(pattern, text, re.IGNORECASE))


def detect_anomalies(log_text):
    """
    ML anomaly detection: parses logs into per-IP feature vectors and
    scores each IP with a trained Isolation Forest. Returns IPs flagged
    as behaviorally anomalous, independent of the regex signatures above —
    this catches things with no known pattern (e.g. a slow brute force
    under the pattern threshold, or unusual volume/timing).
    """
    events = parse_log_text(log_text)
    ip_features = build_ip_features(events)

    if not ip_features:
        return []

    model = _load_model()
    anomalies = []
    for ip, feats in ip_features.items():
        vec = features_to_vector(feats)
        pred = model.predict([vec])[0]          # 1 = normal, -1 = anomaly
        score = model.score_samples([vec])[0]    # lower = more anomalous

        if pred == -1:
            reasons = []
            if feats['failed_auth_ratio'] > 0.5:
                reasons.append(f"{feats['failed_auth_ratio']*100:.0f}% failed auth rate")
            if feats['request_rate_per_sec'] > 1:
                reasons.append(f"{feats['request_rate_per_sec']:.2f} req/sec (high volume)")
            if feats['distinct_paths'] > 25:
                reasons.append(f"{feats['distinct_paths']} distinct paths hit (scan-like)")
            if feats['off_hours_ratio'] > 0.5:
                reasons.append(f"{feats['off_hours_ratio']*100:.0f}% activity outside 06:00-22:00")
            if feats['avg_line_length'] > 400:
                reasons.append("unusually large request/response sizes")
            if not reasons:
                reasons.append("statistically unusual combination of request behavior")

            anomalies.append({
                "ip": ip,
                "anomaly_score": round(float(score), 3),
                "request_count": feats['request_count'],
                "reasons": reasons,
            })

    anomalies.sort(key=lambda a: a['anomaly_score'])
    return anomalies


def analyze_logs(log_text):
    """
    Main function — analyzes raw log text and returns findings from
    both the regex rule set and the ML anomaly detector.
    """
    if not log_text or len(log_text.strip()) < 10:
        return {"error": "Please provide log text to analyze"}

    findings = []
    all_severities = []

    for attack in ATTACK_PATTERNS:
        matches = count_occurrences(attack["pattern"], log_text)
        if matches > 0:
            findings.append({
                "attack_type": attack["name"],
                "severity": attack["severity"],
                "occurrences": matches,
                "description": attack["description"],
                "recommendation": attack["recommendation"]
            })
            all_severities.append(attack["severity"])

    ips_found = extract_ips_from_logs(log_text)
    log_lines = [l for l in log_text.strip().split('\n') if l.strip()]

    try:
        anomalies = detect_anomalies(log_text)
    except Exception:
        anomalies = []

    if anomalies:
        all_severities.append("High")

    if "Critical" in all_severities:
        overall_severity = "Critical"
    elif "High" in all_severities:
        overall_severity = "High"
    elif "Medium" in all_severities:
        overall_severity = "Medium"
    elif findings:
        overall_severity = "Low"
    else:
        overall_severity = "Clean"

    if not findings and not anomalies:
        summary = "No known attack patterns or behavioral anomalies detected. Logs appear clean."
    else:
        parts = []
        if findings:
            attack_names = [f["attack_type"] for f in findings]
            parts.append(f"{len(findings)} signature-based threat(s): {', '.join(attack_names)}")
        if anomalies:
            parts.append(f"{len(anomalies)} IP(s) flagged by ML anomaly detection")
        summary = f"{'; '.join(parts)}. Overall severity: {overall_severity}."

    return {
        "summary": summary,
        "overall_severity": overall_severity,
        "findings": findings,
        "anomalies": anomalies,
        "ips_found": ips_found,
        "log_lines_analyzed": len(log_lines),
        "threat_count": len(findings) + len(anomalies)
    }

# Test it
if __name__ == '__main__':
    sample_log = """
192.168.1.105 - - [23/Jun/2026:10:15:01] "POST /login HTTP/1.1" 401 -
192.168.1.105 - - [23/Jun/2026:10:15:02] "POST /login HTTP/1.1" 401 -
192.168.1.105 - - [23/Jun/2026:10:15:03] "POST /login HTTP/1.1" 401 -
192.168.1.105 - - [23/Jun/2026:10:15:04] Failed password for root
10.0.0.55 - - [23/Jun/2026:10:16:01] "GET /search?q=UNION SELECT * FROM users HTTP/1.1" 200 -
10.0.0.55 - - [23/Jun/2026:10:16:05] "GET /page?file=../../etc/passwd HTTP/1.1" 200 -
"""
    result = analyze_logs(sample_log)
    print("Findings:", len(result['findings']))
    for f in result['findings']:
        print(f" - {f['attack_type']} ({f['severity']}): {f['occurrences']} occurrences")
    print("Anomalies:", len(result['anomalies']))
    for a in result['anomalies']:
        print(f" - {a['ip']} (score {a['anomaly_score']}): {a['reasons']}")
