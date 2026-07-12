# =============================================================
# TRAIN ANOMALY MODEL — run once to produce model.pkl
# Trains an Isolation Forest on per-IP log features.
# =============================================================

import random
import pickle
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from log_features import FEATURE_ORDER

random.seed(42)

def make_normal_sample():
    return {
        'request_count': random.randint(3, 40),
        'failed_auth_ratio': random.uniform(0, 0.15),
        'distinct_paths': random.randint(1, 8),
        'distinct_status_codes': random.randint(1, 3),
        'avg_line_length': random.uniform(60, 140),
        'max_line_length': random.uniform(80, 180),
        'request_rate_per_sec': random.uniform(0.01, 0.5),
        'off_hours_ratio': random.uniform(0, 0.2),
        'error_status_ratio': random.uniform(0, 0.1),
    }

def make_attack_sample():
    kind = random.choice(['brute_force', 'scan', 'exfil'])
    if kind == 'brute_force':
        return {
            'request_count': random.randint(50, 400),
            'failed_auth_ratio': random.uniform(0.7, 1.0),
            'distinct_paths': random.randint(1, 2),
            'distinct_status_codes': random.randint(1, 2),
            'avg_line_length': random.uniform(60, 120),
            'max_line_length': random.uniform(80, 150),
            'request_rate_per_sec': random.uniform(2, 20),
            'off_hours_ratio': random.uniform(0.3, 1.0),
            'error_status_ratio': random.uniform(0.7, 1.0),
        }
    if kind == 'scan':
        return {
            'request_count': random.randint(80, 500),
            'failed_auth_ratio': random.uniform(0, 0.2),
            'distinct_paths': random.randint(30, 150),
            'distinct_status_codes': random.randint(3, 6),
            'avg_line_length': random.uniform(50, 100),
            'max_line_length': random.uniform(70, 140),
            'request_rate_per_sec': random.uniform(3, 25),
            'off_hours_ratio': random.uniform(0.2, 0.9),
            'error_status_ratio': random.uniform(0.4, 0.9),
        }
    return {
        'request_count': random.randint(10, 60),
        'failed_auth_ratio': random.uniform(0, 0.1),
        'distinct_paths': random.randint(1, 5),
        'distinct_status_codes': random.randint(1, 2),
        'avg_line_length': random.uniform(500, 2000),
        'max_line_length': random.uniform(1000, 5000),
        'request_rate_per_sec': random.uniform(0.5, 5),
        'off_hours_ratio': random.uniform(0.4, 1.0),
        'error_status_ratio': random.uniform(0, 0.1),
    }

def build_training_set(n_normal=400, n_attack=60):
    rows = []
    for _ in range(n_normal):
        rows.append([make_normal_sample()[k] for k in FEATURE_ORDER])
    for _ in range(n_attack):
        rows.append([make_attack_sample()[k] for k in FEATURE_ORDER])
    return rows

if __name__ == '__main__':
    X = build_training_set()

    # contamination='auto' with a mostly-normal training set lets the
    # model learn a general boundary rather than overfitting to the
    # synthetic attack ratio we happened to generate.
    model = IsolationForest(
        n_estimators=150,
        contamination=0.12,
        random_state=42,
    )
    model.fit(X)

    with open('anomaly_model.pkl', 'wb') as f:
        pickle.dump(model, f)

    print(f"Trained on {len(X)} samples, {len(FEATURE_ORDER)} features.")
    print("Saved to anomaly_model.pkl")

    # quick sanity check
    test_normal = [make_normal_sample()[k] for k in FEATURE_ORDER]
    test_attack = [make_attack_sample()[k] for k in FEATURE_ORDER]
    print("Normal sample  → predict:", model.predict([test_normal])[0],
          " score:", round(model.score_samples([test_normal])[0], 3))
    print("Attack sample  → predict:", model.predict([test_attack])[0],
          " score:", round(model.score_samples([test_attack])[0], 3))
