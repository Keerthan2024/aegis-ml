"""
Evaluate AEGIS Models on CICIDS2017 20% Holdout Test Set
---------------------------------------------------------
Reproduces the exact 80/20 stratified split used during training
(using random_state=42) and runs the saved models against the test
partition WITHOUT retraining — ensuring a true holdout evaluation.
"""
import sys, math
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent))

import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score, confusion_matrix

from backend.core.schemas import UnifiedEvent
from backend.core.config import PORT_RISK
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.threat_classifier import ThreatClassifier
from backend.detection.model_trainer import load_flexible_dataset, extract_features, calculate_failed_auth_rate

CLASSES = ThreatClassifier.CLASSES

LABEL_MAP = {
    'BENIGN': 'benign',
    'PortScan': 'lateral_movement',
    'FTP-Patator': 'brute_force',
    'SSH-Patator': 'brute_force',
    'Infiltration': 'data_exfiltration',
    'Bot': 'c2_beaconing',
    'Web Attack \x96 Brute Force': 'brute_force',
    'Web Attack - Brute Force': 'brute_force',
    'DDoS': 'c2_beaconing',
    'DoS Hulk': 'c2_beaconing',
    'DoS GoldenEye': 'c2_beaconing',
}

MAX_ROWS_PER_FILE = 1000  # Must match training config

def main():
    # --- 1. Load ALL CICIDS CSVs (same as training) ---
    events = []
    dataset_dir = Path("datasets")
    if not dataset_dir.exists():
        print("ERROR: datasets/ folder not found. Cannot evaluate.")
        return

    print("="*60)
    print("AEGIS Holdout Evaluation — CICIDS2017 Real-World Test")
    print("="*60)
    print("\n[1/4] Loading CICIDS datasets...")
    for csv_file in sorted(dataset_dir.glob("*.csv")):
        chunk = load_flexible_dataset(str(csv_file), max_rows=MAX_ROWS_PER_FILE)
        events.extend(chunk)
        print(f"      {csv_file.name}: {len(chunk)} events")

    print(f"\n      Total loaded: {len(events)} events")

    if not events:
        print("No events found.")
        return

    # --- 2. Reproduce the EXACT same 80/20 split ---
    print("\n[2/4] Reproducing 80/20 stratified split (random_state=42)...")
    all_labels = []
    for event in events:
        label = event.attack_type if event.attack_type else "benign"
        if label not in CLASSES:
            label = "benign"
        all_labels.append(label)

    train_events, test_events, y_train, y_test = train_test_split(
        events, all_labels,
        test_size=0.2,
        stratify=all_labels,
        random_state=42
    )
    print(f"      Train: {len(train_events)} events  |  Test: {len(test_events)} events")

    from collections import Counter
    test_dist = Counter(y_test)
    print("\n      Test-set class distribution:")
    for cls, cnt in sorted(test_dist.items()):
        print(f"        {cls:<22} {cnt:>6} samples")

    # --- 3. Load saved models ---
    print("\n[3/4] Loading saved models from data/models/...")
    profiler = BehavioralBaselineProfiler()
    profiler.load()

    if_detector = IsolationForestDetector()
    if_detector.load()

    classifier = ThreatClassifier()
    classifier.load()
    if not classifier.is_fitted:
        print("ERROR: Classifier not found. Run `python -m backend.detection.model_trainer train` first.")
        return

    # --- 4. Build feature vectors for TEST set ONLY ---
    print("\n[4/4] Extracting features for 20% test set...")
    failed_auth_rates = calculate_failed_auth_rate(test_events)

    X_test = []
    for event in test_events:
        if_score = if_detector.predict(event)
        baseline_dev = profiler.compute_deviation_score(event)
        auth_rate = failed_auth_rates.get(event.event_id, 0.0)
        X_test.append(extract_features(event, if_score, baseline_dev, profiler, auth_rate))

    X_test = np.array(X_test)
    y_test = np.array(y_test)

    # --- 5. Predict and print metrics ---
    y_pred = classifier.model.predict(X_test)

    print("\n" + "="*60)
    print("HOLDOUT TEST SET — EVALUATION RESULTS")
    print("="*60)

    # Weighted F1
    weighted_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    macro_f1    = f1_score(y_test, y_pred, average="macro",    zero_division=0)
    print(f"\n  Weighted F1 Score : {weighted_f1:.4f}")
    print(f"  Macro F1 Score    : {macro_f1:.4f}")

    # Per-class report
    print("\n  Per-Class Classification Report:")
    print(classification_report(y_test, y_pred, labels=CLASSES, zero_division=0))

    # Confusion matrix
    print("  Confusion Matrix (rows=actual, cols=predicted):")
    cm = confusion_matrix(y_test, y_pred, labels=CLASSES)
    header = f"  {'':>20}" + "".join(f"{c[:8]:>10}" for c in CLASSES)
    print(header)
    for i, row in enumerate(cm):
        print(f"  {CLASSES[i]:>20}" + "".join(f"{v:>10}" for v in row))

    print("\n" + "="*60)
    print("Evaluation complete.")


if __name__ == "__main__":
    main()
