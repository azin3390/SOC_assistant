# =============================================================
# LOG FEATURES — parses raw log text into structured events and
# builds numeric per-IP feature vectors for anomaly detection.
# =============================================================

import re
from collections import defaultdict
from datetime import datetime

# Matches common log timestamp formats, e.g. [23/Jun/2026:10:15:01]
TIMESTAMP_PATTERN = re.compile(
    r'\[?(\d{1,2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\]?'
)
IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
STATUS_PATTERN = re.compile(r'"\s(\d{3})\s')
FAILED_AUTH_PATTERN = re.compile(
    r'Failed password|authentication failure|Invalid user|failed login|401',
    re.IGNORECASE
)
PATH_PATTERN = re.compile(r'"[A-Z]+\s(\S+)\s')


def parse_log_line(line):
    """Extract structured fields from a single raw log line. Any field
    that can't be found is left as None rather than guessed."""
    ip_match = IP_PATTERN.search(line)
    ts_match = TIMESTAMP_PATTERN.search(line)
    status_match = STATUS_PATTERN.search(line)
    path_match = PATH_PATTERN.search(line)

    ts = None
    if ts_match:
        try:
            ts = datetime.strptime(ts_match.group(1), '%d/%b/%Y:%H:%M:%S')
        except ValueError:
            ts = None

    return {
        'raw': line,
        'ip': ip_match.group(1) if ip_match else None,
        'timestamp': ts,
        'status': int(status_match.group(1)) if status_match else None,
        'path': path_match.group(1) if path_match else None,
        'is_failed_auth': bool(FAILED_AUTH_PATTERN.search(line)),
        'length': len(line),
    }


def parse_log_text(log_text):
    """Parse raw multi-line log text into a list of structured events."""
    lines = [l for l in log_text.strip().split('\n') if l.strip()]
    return [parse_log_line(l) for l in lines]


def build_ip_features(events):
    """
    Group parsed events by source IP and compute a numeric feature
    vector per IP. These features are what the anomaly model sees —
    no raw text goes into the model, only these numbers.

    Returns: dict {ip: {feature_name: value}}
    """
    by_ip = defaultdict(list)
    for e in events:
        if e['ip']:
            by_ip[e['ip']].append(e)

    features = {}
    for ip, evs in by_ip.items():
        n = len(evs)
        failed = sum(1 for e in evs if e['is_failed_auth'])
        distinct_paths = len(set(e['path'] for e in evs if e['path']))
        distinct_status = len(set(e['status'] for e in evs if e['status'] is not None))
        avg_len = sum(e['length'] for e in evs) / n
        max_len = max(e['length'] for e in evs)

        timestamps = sorted(e['timestamp'] for e in evs if e['timestamp'])
        if len(timestamps) >= 2:
            span_seconds = max(1, (timestamps[-1] - timestamps[0]).total_seconds())
            request_rate = n / span_seconds
        else:
            request_rate = 0.0

        off_hours = 0
        for e in evs:
            if e['timestamp'] and (e['timestamp'].hour < 6 or e['timestamp'].hour >= 22):
                off_hours += 1
        off_hours_ratio = off_hours / n if n else 0.0

        error_statuses = sum(1 for e in evs if e['status'] and e['status'] >= 400)

        features[ip] = {
            'request_count': n,
            'failed_auth_ratio': failed / n if n else 0.0,
            'distinct_paths': distinct_paths,
            'distinct_status_codes': distinct_status,
            'avg_line_length': avg_len,
            'max_line_length': max_len,
            'request_rate_per_sec': request_rate,
            'off_hours_ratio': off_hours_ratio,
            'error_status_ratio': error_statuses / n if n else 0.0,
        }

    return features


FEATURE_ORDER = [
    'request_count',
    'failed_auth_ratio',
    'distinct_paths',
    'distinct_status_codes',
    'avg_line_length',
    'max_line_length',
    'request_rate_per_sec',
    'off_hours_ratio',
    'error_status_ratio',
]


def features_to_vector(feature_dict):
    """Convert a feature dict into an ordered list, matching FEATURE_ORDER,
    for feeding into the model."""
    return [feature_dict[k] for k in FEATURE_ORDER]
