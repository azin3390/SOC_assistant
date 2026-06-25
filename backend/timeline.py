import re
from collections import defaultdict

def parse_timestamps(log_text):
    events = []
    lines = log_text.strip().split('\n')
    hour_counts = defaultdict(int)
    attack_timeline = []

    for line in lines:
        if not line.strip():
            continue

        # Match time ONLY inside brackets like [23/Jun/2026:10:15:01]
        # or standalone HH:MM:SS that isn't part of a year
        time_match = re.search(r'[\[T ](\d{2}):(\d{2}):(\d{2})[\] ]', line)
        if not time_match:
            # fallback — find HH:MM:SS not preceded by 4 digits (year)
            time_match = re.search(r'(?<!\d)([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?!\d)', line)

        if time_match:
            hour = int(time_match.group(1))
            if 0 <= hour <= 23:  # Valid hour only
                hour_counts[hour] += 1
                time_str = time_match.group(0).strip('[ ]T')

                event_type = classify_log_line(line)
                if event_type:
                    attack_timeline.append({
                        "time": time_str,
                        "event": event_type["name"],
                        "severity": event_type["severity"],
                        "line": line.strip()[:100]
                    })

    return {
        "hour_distribution": dict(sorted(hour_counts.items())),
        "attack_timeline": attack_timeline[:20],
        "peak_hour": max(hour_counts, key=hour_counts.get) if hour_counts else None,
        "total_events": len(lines)
    }

def classify_log_line(line):
    line_lower = line.lower()
    if any(w in line_lower for w in ['failed password', 'authentication failure', 'invalid user']):
        return {"name": "Failed Login", "severity": "High"}
    elif any(w in line_lower for w in ['union select', 'or 1=1', 'drop table']):
        return {"name": "SQL Injection", "severity": "Critical"}
    elif any(w in line_lower for w in ['../','etc/passwd', 'etc/shadow']):
        return {"name": "Directory Traversal", "severity": "Critical"}
    elif any(w in line_lower for w in ['<script', 'javascript:', 'onerror=']):
        return {"name": "XSS Attempt", "severity": "High"}
    elif '404' in line:
        return {"name": "Not Found (Scanning?)", "severity": "Low"}
    elif '500' in line:
        return {"name": "Server Error", "severity": "Medium"}
    elif any(w in line_lower for w in ['sqlmap', 'nikto', 'nmap', 'masscan']):
        return {"name": "Scanner Detected", "severity": "High"}
    elif ':4444' in line or ':1337' in line:
        return {"name": "Suspicious Port", "severity": "High"}
    return None

def generate_timeline_html(log_text):
    data = parse_timestamps(log_text)
    timeline_events = data["attack_timeline"]
    hour_dist = data["hour_distribution"]

    severity_colors = {
        "Critical": "#ef4444",
        "High": "#fb923c",
        "Medium": "#fbbf24",
        "Low": "#4ade80"
    }

    timeline_items = ""
    for event in timeline_events:
        color = severity_colors.get(event["severity"], "#94a3b8")
        timeline_items += f"""
        <div style="display:flex;gap:12px;align-items:flex-start;margin-bottom:10px">
            <div style="background:{color};color:white;padding:3px 8px;border-radius:4px;font-size:11px;white-space:nowrap;font-weight:600">{event['time']}</div>
            <div>
                <div style="font-size:12px;font-weight:600;color:{color}">{event['event']}</div>
                <div style="font-size:11px;color:#64748b;font-family:monospace">{event['line'][:80]}</div>
            </div>
        </div>"""

    max_count = max(hour_dist.values()) if hour_dist else 1
    bars = ""
    for hour in range(24):
        count = hour_dist.get(hour, 0)
        height = int((count / max_count) * 60) if max_count > 0 else 0
        color = "#ef4444" if count == max_count and count > 0 else "#38bdf8"
        bars += f"""
        <div style="display:flex;flex-direction:column;align-items:center;gap:2px">
            <div style="font-size:9px;color:#64748b">{count if count > 0 else ''}</div>
            <div style="width:18px;height:{max(height,2)}px;background:{color};border-radius:2px 2px 0 0"></div>
            <div style="font-size:9px;color:#475569">{hour:02d}</div>
        </div>"""

    if not timeline_items:
        timeline_items = '<div style="color:#475569;padding:20px;text-align:center">No timestamped events found in logs</div>'

    return {
        "html": f"""
        <div style="font-family:-apple-system,sans-serif">
            <div style="margin-bottom:16px">
                <div style="font-size:12px;font-weight:600;color:#94a3b8;text-transform:uppercase;margin-bottom:8px">Activity by Hour</div>
                <div style="display:flex;align-items:flex-end;gap:1px;height:80px;background:#0a0e1a;padding:8px;border-radius:6px">{bars}</div>
                <div style="font-size:11px;color:#475569;margin-top:4px">
                    Peak activity: {f"{data['peak_hour']:02d}:00" if data['peak_hour'] is not None else 'N/A'} | Total lines: {data['total_events']}
                </div>
            </div>
            <div style="font-size:12px;font-weight:600;color:#94a3b8;text-transform:uppercase;margin-bottom:8px">Attack Timeline</div>
            <div style="max-height:300px;overflow-y:auto">{timeline_items}</div>
        </div>""",
        "stats": data
    }

if __name__ == '__main__':
    sample = """
    192.168.1.105 - - [23/Jun/2026:10:15:01] Failed password for root
    192.168.1.105 - - [23/Jun/2026:10:15:03] Failed password for admin
    10.0.0.55 - - [23/Jun/2026:10:16:01] GET /search?q=UNION SELECT * FROM users
    10.0.0.55 - - [23/Jun/2026:10:16:05] GET /page?file=../../etc/passwd
    192.168.1.200 - - [23/Jun/2026:11:22:01] GET /admin HTTP/1.1 404
    192.168.1.200 - - [23/Jun/2026:11:22:05] GET /wp-admin HTTP/1.1 404
    """
    result = generate_timeline_html(sample)
    print("Timeline events found:", len(result['stats']['attack_timeline']))
    print("Hour distribution:", result['stats']['hour_distribution'])
    print("Peak hour:", result['stats']['peak_hour'])
