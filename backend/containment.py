# =============================================================
# TIME-TO-CONTAINMENT OPTIMIZER
# Estimates attack escalation timeline and recommends fastest
# containment actions to beat the attacker's clock
# =============================================================

import re

# Breach escalation stages with typical time-since-initial-access (minutes)
# based on common incident response research (dwell time studies)
STAGES = [
    {"name": "Initial Access", "keywords": ["phishing", "clicked", "malicious url", "initial access", "opened attachment", "received email"], "minutes": 0, "icon": "📧"},
    {"name": "Credential Theft", "keywords": ["credential", "password stolen", "mimikatz", "dumped", "login compromised", "stolen credentials", "brute force", "failed password"], "minutes": 10, "icon": "🔑"},
    {"name": "Lateral Movement", "keywords": ["lateral movement", "smb", "psexec", "rdp", "pass the hash", "spread to", "moved to", "wmi"], "minutes": 45, "icon": "↔️"},
    {"name": "Privilege Escalation", "keywords": ["privilege escalation", "admin rights", "domain admin", "escalated", "elevated privileges"], "minutes": 70, "icon": "⬆️"},
    {"name": "Data Exfiltration", "keywords": ["exfiltration", "data transfer", "uploaded", "sent to", "stolen data", "exfiltrated", "outbound transfer"], "minutes": 120, "icon": "📤"},
    {"name": "Ransomware Deployment", "keywords": ["ransomware", "encrypted files", "encryption", "ransom note", "files encrypted"], "minutes": 240, "icon": "🔒"},
]

# Candidate containment actions: (name, minutes to execute, applicable stage keywords, priority)
ACTION_POOL = [
    {"action": "Isolate affected host from network", "minutes": 3, "trigger_stages": [1, 2, 3, 4, 5], "priority": 1},
    {"action": "Reset compromised user credentials & force MFA", "minutes": 5, "trigger_stages": [1, 2, 3], "priority": 1},
    {"action": "Revoke active sessions and access tokens", "minutes": 2, "trigger_stages": [1, 2, 3], "priority": 1},
    {"action": "Disable compromised account(s)", "minutes": 2, "trigger_stages": [1, 2, 3], "priority": 1},
    {"action": "Block malicious IP/domain at firewall", "minutes": 4, "trigger_stages": [2, 3, 4, 5], "priority": 2},
    {"action": "Kill malicious process via EDR", "minutes": 5, "trigger_stages": [1, 2, 3, 5], "priority": 2},
    {"action": "Block egress to known exfiltration destinations", "minutes": 5, "trigger_stages": [4], "priority": 1},
    {"action": "Snapshot and isolate unaffected backups immediately", "minutes": 10, "trigger_stages": [5], "priority": 1},
    {"action": "Disable lateral movement paths (segment network)", "minutes": 8, "trigger_stages": [2, 3], "priority": 2},
    {"action": "Notify incident response team & escalate", "minutes": 2, "trigger_stages": [0, 1, 2, 3, 4, 5], "priority": 1},
    {"action": "Preserve logs and memory for forensics", "minutes": 5, "trigger_stages": [0, 1, 2, 3, 4, 5], "priority": 3},
]


def detect_current_stage(text_lower):
    """Find the furthest stage with keyword evidence — assume attacker has
    progressed at least that far."""
    detected_idx = 0
    for i, stage in enumerate(STAGES):
        if any(kw in text_lower for kw in stage["keywords"]):
            detected_idx = i
    return detected_idx


def analyze_containment(text):
    text_lower = text.lower()
    stage_idx = detect_current_stage(text_lower)
    current_stage = STAGES[stage_idx]

    # Build escalation timeline relative to current detected point
    timeline = []
    for i, stage in enumerate(STAGES):
        if i < stage_idx:
            status = "passed"
            minutes_from_now = None
        elif i == stage_idx:
            status = "current"
            minutes_from_now = 0
        else:
            status = "upcoming"
            minutes_from_now = stage["minutes"] - current_stage["minutes"]
        timeline.append({
            "name": stage["name"],
            "icon": stage["icon"],
            "status": status,
            "minutes_from_now": minutes_from_now
        })

    # Find next upcoming milestone (the clock we're racing against)
    next_stage = None
    for t in timeline:
        if t["status"] == "upcoming":
            next_stage = t
            break

    # Select applicable actions for the current stage
    applicable = [a for a in ACTION_POOL if stage_idx in a["trigger_stages"]]
    applicable.sort(key=lambda a: (a["priority"], a["minutes"]))
    top_actions = applicable[:6]

    parallel_time = max((a["minutes"] for a in top_actions), default=0)
    sequential_time = sum(a["minutes"] for a in top_actions)

    # Race status
    if next_stage is None:
        race_status = "critical"
        race_message = f"Attack has already reached the final observed stage ({current_stage['name']}). Focus entirely on eradication and recovery — the race for containment has been lost for this stage."
        race_color = "#FF6B6B"
    else:
        margin = next_stage["minutes_from_now"] - parallel_time
        if margin > 20:
            race_status = "safe"
            race_message = f"You have an estimated {next_stage['minutes_from_now']} minutes before {next_stage['name']} begins. Recommended actions take ~{parallel_time} minutes in parallel — there is a comfortable safety margin."
            race_color = "#10B981"
        elif margin > 0:
            race_status = "urgent"
            race_message = f"You have an estimated {next_stage['minutes_from_now']} minutes before {next_stage['name']} begins. Recommended actions take ~{parallel_time} minutes — act now, the margin is tight."
            race_color = "#FFE66D"
        else:
            race_status = "critical"
            race_message = f"{next_stage['name']} may already be starting or imminent. Recommended actions (~{parallel_time} min) may not complete in time — execute in parallel across multiple responders immediately."
            race_color = "#FF6B6B"

    return {
        "current_stage": current_stage["name"],
        "current_stage_icon": current_stage["icon"],
        "stage_index": stage_idx,
        "timeline": timeline,
        "next_stage": next_stage,
        "recommended_actions": top_actions,
        "parallel_time_minutes": parallel_time,
        "sequential_time_minutes": sequential_time,
        "race_status": race_status,
        "race_message": race_message,
        "race_color": race_color
    }


if __name__ == '__main__':
    test = """
    User received phishing email and clicked malicious link.
    Failed password attempts detected, then a successful login with stolen credentials.
    SMB connections observed spreading to FILESERVER-01 — lateral movement in progress.
    """
    result = analyze_containment(test)
    print(f"Current stage: {result['current_stage']} ({result['stage_index']})")
    print(f"Race status: {result['race_status']} — {result['race_message']}")
    print(f"Top actions: {[a['action'] for a in result['recommended_actions']]}")
    print(f"Parallel time: {result['parallel_time_minutes']} min")
