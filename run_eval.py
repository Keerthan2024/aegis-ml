import numpy as np
from pathlib import Path
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score, confusion_matrix
from backend.detection.model_trainer import load_flexible_dataset, extract_features, calculate_failed_auth_rate
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.threat_classifier import ThreatClassifier

CLASSES = ThreatClassifier.CLASSES
events = []
for csv_file in sorted(Path('datasets').glob('*.csv')):
    chunk = load_flexible_dataset(str(csv_file), max_rows=1000)
    events.extend(chunk)

print(f'Total events: {len(events)}')
all_labels = [e.attack_type if e.attack_type and e.attack_type in CLASSES else 'benign' for e in events]
print('Class distribution:', dict(Counter(all_labels)))

_, test_events, _, y_test = train_test_split(
    events, all_labels, test_size=0.2, stratify=all_labels, random_state=42
)

p = BehavioralBaselineProfiler()
p.load()
ifd = IsolationForestDetector()
ifd.load()
clf = ThreatClassifier()
clf.load()

far = calculate_failed_auth_rate(test_events)
X = np.array([
    extract_features(e, ifd.predict(e), p.compute_deviation_score(e), p, far.get(e.event_id, 0.0))
    for e in test_events
])
y = np.array(y_test)
pred = clf.model.predict(X)

print()
print('=' * 60)
print('AEGIS CICIDS2017 HOLDOUT TEST RESULTS (20% test set)')
print('=' * 60)
print(f'Test Set Size    : {len(y)} events')
print(f'Weighted F1      : {f1_score(y, pred, average="weighted", zero_division=0):.4f}')
print(f'Macro F1         : {f1_score(y, pred, average="macro", zero_division=0):.4f}')
print()
print(classification_report(y, pred, labels=CLASSES, zero_division=0))
print('Confusion Matrix (rows=actual, cols=predicted):')
print(f"{'':>25}", "  ".join(f"{c[:6]:>8}" for c in CLASSES))
cm = confusion_matrix(y, pred, labels=CLASSES)
for i, row in enumerate(cm):
    print(f'{CLASSES[i]:>25}', "  ".join(f'{v:>8}' for v in row))
print('=' * 60)
