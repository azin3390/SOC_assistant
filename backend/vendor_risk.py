# =============================================================
# VENDOR RISK ANALYZER
# Scores third-party vendor security documentation
# =============================================================

import re

# Security controls to check for — (name, keywords indicating present, weight)
SECURITY_CONTROLS = [
    {"name": "Multi-Factor Authentication", "keywords": ["mfa", "multi-factor", "two-factor", "2fa"], "weight": 10},
    {"name": "Data Encryption", "keywords": ["encryption", "encrypted", "aes-256", "tls", "at rest and in transit"], "weight": 12},
    {"name": "SOC 2 Compliance", "keywords": ["soc 2", "soc2", "soc ii"], "weight": 10},
    {"name": "ISO 27001 Certification", "keywords": ["iso 27001", "iso/iec 27001"], "weight": 10},
    {"name": "Incident Response Plan", "keywords": ["incident response", "incident response plan", "irp"], "weight": 10},
    {"name": "Regular Penetration Testing", "keywords": ["penetration test", "pentest", "pen test"], "weight": 8},
    {"name": "Access Control Policy", "keywords": ["access control", "least privilege", "role-based access", "rbac"], "weight": 8},
    {"name": "Employee Security Training", "keywords": ["security training", "security awareness", "employee training"], "weight": 6},
    {"name": "Data Backup & Recovery", "keywords": ["backup", "disaster recovery", "business continuity"], "weight": 8},
    {"name": "Vulnerability Management", "keywords": ["vulnerability management", "vulnerability scanning", "patch management"], "weight": 8},
    {"name": "Data Retention Policy", "keywords": ["data retention", "retention policy", "data deletion"], "weight": 5},
    {"name": "Compliance (GDPR/CCPA)", "keywords": ["gdpr", "ccpa", "data privacy regulation"], "weight": 5},
]

# Phrases that indicate red flags / concerning responses
CONCERNING_PHRASES = [
    {"phrase": r"do(es)?\s+not\s+encrypt", "flag": "Admits data is NOT encrypted", "severity": "Critical"},
    {"phrase": r"no\s+formal\s+(policy|process|procedure)", "flag": "No formal policy/process in place", "severity": "High"},
    {"phrase": r"planned\s+for\s+(the\s+)?future|not\s+yet\s+implemented|currently\s+in\s+progress", "flag": "Control is not yet implemented", "severity": "High"},
    {"phrase": r"unable\s+to\s+provide|cannot\s+provide|not\s+available\s+at\s+this\s+time", "flag": "Vendor unable/unwilling to provide evidence", "severity": "High"},
    {"phrase": r"no\s+(dedicated\s+)?security\s+team", "flag": "No dedicated security team", "severity": "Medium"},
    {"phrase": r"shared\s+(password|credential)", "flag": "Shared password/credential practice", "severity": "Critical"},
    {"phrase": r"no\s+audit|never\s+been\s+audited", "flag": "No security audits performed", "severity": "High"},
    {"phrase": r"third[- ]party\s+access\s+(is\s+)?not\s+monitored", "flag": "Third-party access not monitored", "severity": "Medium"},
    {"phrase": r"data\s+stored\s+(indefinitely|forever|permanently)", "flag": "No data retention limits", "severity": "Medium"},
    {"phrase": r"no\s+breach\s+notification|not\s+required\s+to\s+notify", "flag": "No breach notification commitment", "severity": "Critical"},
]


def analyze_vendor_document(text):
    """
    Analyzes vendor questionnaire/policy/audit text and returns a risk assessment.
    """
    text_lower = text.lower()

    controls_found = []
    controls_missing = []
    max_score = sum(c["weight"] for c in SECURITY_CONTROLS)
    earned_score = 0

    negation_words = ["not", "no ", "without", "lack of", "never", "absence of", "n't", "unable to", "does not"]

    def keyword_negated(text, keyword):
        for m in re.finditer(re.escape(keyword), text):
            window_start = max(0, m.start() - 40)
            window = text[window_start:m.start()]
            if any(neg in window for neg in negation_words):
                return True
        return False

    for control in SECURITY_CONTROLS:
        matched_kw = None
        for kw in control["keywords"]:
            if kw in text_lower:
                matched_kw = kw
                break
        if matched_kw and not keyword_negated(text_lower, matched_kw):
            controls_found.append(control["name"])
            earned_score += control["weight"]
        else:
            controls_missing.append(control["name"])

    # Detect concerning phrases
    concerning_flags = []
    for item in CONCERNING_PHRASES:
        matches = re.findall(item["phrase"], text_lower)
        if matches:
            concerning_flags.append({
                "flag": item["flag"],
                "severity": item["severity"],
                "occurrences": len(matches)
            })

    # Base score from controls present (0-100 scale)
    base_score = round((earned_score / max_score) * 100) if max_score > 0 else 0

    # Penalize for concerning flags
    penalty = 0
    for flag in concerning_flags:
        if flag["severity"] == "Critical":
            penalty += 15 * flag["occurrences"]
        elif flag["severity"] == "High":
            penalty += 8 * flag["occurrences"]
        else:
            penalty += 4 * flag["occurrences"]

    final_score = max(0, min(100, base_score - penalty))

    # Risk level (inverse of score — higher score = lower risk)
    if final_score >= 80:
        risk_level = "Low Risk"
        risk_color = "#10B981"
    elif final_score >= 60:
        risk_level = "Medium Risk"
        risk_color = "#FFE66D"
    elif final_score >= 35:
        risk_level = "High Risk"
        risk_color = "#FF9F43"
    else:
        risk_level = "Critical Risk"
        risk_color = "#FF6B6B"

    critical_flags = sum(1 for f in concerning_flags if f["severity"] == "Critical")

    summary = f"Vendor demonstrates {len(controls_found)} of {len(SECURITY_CONTROLS)} expected security controls."
    if concerning_flags:
        summary += f" {len(concerning_flags)} concerning statement(s) identified in the documentation."
    if critical_flags > 0:
        summary += f" {critical_flags} CRITICAL red flag(s) require immediate follow-up before engagement."
    if not concerning_flags and len(controls_missing) <= 2:
        summary += " Overall documentation quality is strong."

    recommendations = []
    if critical_flags > 0:
        recommendations.append("🚨 Do not proceed until critical gaps are resolved or compensating controls are agreed")
    if "Data Encryption" in controls_missing:
        recommendations.append("🔒 Require written confirmation of encryption standards before data sharing")
    if "Incident Response Plan" in controls_missing:
        recommendations.append("📋 Request the vendor's incident response plan and breach notification SLA")
    if "SOC 2 Compliance" in controls_missing and "ISO 27001 Certification" in controls_missing:
        recommendations.append("📜 Request a recognized compliance certification (SOC 2 or ISO 27001)")
    if len(controls_missing) > 6:
        recommendations.append("⚠️ Schedule a security review call — documentation shows significant gaps")
    recommendations.append("📅 Reassess this vendor's risk score annually or after any reported incident")

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "controls_found": controls_found,
        "controls_missing": controls_missing,
        "concerning_flags": concerning_flags,
        "summary": summary,
        "recommendations": recommendations,
        "total_controls": len(SECURITY_CONTROLS),
        "controls_found_count": len(controls_found)
    }


if __name__ == '__main__':
    test = """
    Our company uses AES-256 encryption for data at rest and TLS for data in transit.
    We are SOC 2 Type II certified. However, we do not currently have a formal incident response plan.
    Multi-factor authentication is required for all employee accounts.
    Unfortunately, we do not encrypt backup data and have no dedicated security team.
    """
    result = analyze_vendor_document(test)
    print(f"Risk Score: {result['risk_score']}/100 — {result['risk_level']}")
    print(f"Controls found: {result['controls_found']}")
    print(f"Concerning flags: {result['concerning_flags']}")
