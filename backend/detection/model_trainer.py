import json
import math
import numpy as np
from typing import List, Dict, Tuple
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, classification_report
from collections import defaultdict
from datetime import datetime, timedelta
import pandas as pd

from backend.core.schemas import UnifiedEvent
from backend.core.config import PORT_RISK
from backend.detection.baseline_profiler import BehavioralBaselineProfiler
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.threat_classifier import ThreatClassifier

def load_flexible_dataset(file_path: str, max_rows: int = 15000) -> List[UnifiedEvent]:
    events = []
    if not Path(file_path).exists():
        print(f"File not found: {file_path}")
        return events
        
    try:
        if str(file_path).endswith('.csv'):
            df = pd.read_csv(file_path, low_memory=False)  # full read
        else:
            try:
                df = pd.read_json(file_path, lines=True)
            except:
                df = pd.read_json(file_path)
                
        df.columns = df.columns.str.strip()
        # Strip whitespace from string values to handle CICIDS leading spaces
        if 'Label' in df.columns:
            df['Label'] = df['Label'].str.strip()
        col_map = {
            'source ip': 'src_ip', 'destination ip': 'dst_ip',
            'label': 'attack_type', 'src': 'src_entity', 'dst': 'dst_entity',
            'timestamp': 'timestamp', 'time': 'timestamp',
            'destination port': 'dst_port', 'protocol': 'protocol',
            'total length of fwd packets': 'bytes_sent',
            'total length of bwd packets': 'bytes_received',
            'flow duration': 'duration_ms',
        }
        df = df.rename(columns=lambda x: col_map.get(x.lower(), x))

        # Map CICIDS labels to our class labels
        label_map = {
            'BENIGN': 'benign',
            'PortScan': 'lateral_movement',
            'FTP-Patator': 'brute_force',
            'SSH-Patator': 'brute_force',
            'Infiltration': 'data_exfiltration',
            'Bot': 'c2_beaconing',
            'Web Attack \x96 Brute Force': 'brute_force',
            'Web Attack - Brute Force': 'brute_force',
            'Web Attack - XSS': 'brute_force',
            'Web Attack - Sql Injection': 'brute_force',
            'DDoS': 'c2_beaconing',
            'DoS Hulk': 'c2_beaconing',
            'DoS GoldenEye': 'c2_beaconing',
            'DoS Slowhttptest': 'c2_beaconing',
            'DoS slowloris': 'c2_beaconing',
            'Heartbleed': 'data_exfiltration',
        }
        if 'attack_type' in df.columns:
            df['attack_type'] = df['attack_type'].str.strip() if df['attack_type'].dtype == object else df['attack_type']
            df['attack_type'] = df['attack_type'].map(lambda x: label_map.get(str(x).strip(), 'benign'))
        
        # Stratified per-label sampling:
        # Cap benign at max_rows; cap each attack class at max_rows//2 so attacks are well-represented
        if 'attack_type' in df.columns:
            sampled_dfs = []
            benign_df = df[df['attack_type'] == 'benign']
            if len(benign_df) > max_rows:
                sampled_dfs.append(benign_df.sample(n=max_rows, random_state=42))
            else:
                sampled_dfs.append(benign_df)
            attack_cap = max(200, max_rows // 2)
            # Rare classes (data_exfiltration) — take ALL available samples
            RARE_CLASSES = {'data_exfiltration'}
            for cls in df['attack_type'].unique():
                if cls == 'benign':
                    continue
                cls_df = df[df['attack_type'] == cls]
                if cls in RARE_CLASSES:
                    # No cap — always use every available sample for rare classes
                    sampled_dfs.append(cls_df)
                elif len(cls_df) > attack_cap:
                    sampled_dfs.append(cls_df.sample(n=attack_cap, random_state=42))
                else:
                    sampled_dfs.append(cls_df)
            df = pd.concat(sampled_dfs).reset_index(drop=True)
                
        df = df.replace({np.nan: None})
        
        for _, row in df.iterrows():
            d = row.to_dict()
            if 'timestamp' not in d or d['timestamp'] is None:
                d['timestamp'] = datetime.now()
            elif isinstance(d['timestamp'], str):
                try:
                    d['timestamp'] = pd.to_datetime(d['timestamp'])
                except:
                    d['timestamp'] = datetime.now()
                    
            if 'layer' not in d: d['layer'] = 'network'
            if 'src_entity' not in d: d['src_entity'] = d.get('src_ip', 'unknown')
            if 'dst_entity' not in d: d['dst_entity'] = d.get('dst_ip', 'unknown')
            if 'src_internal' not in d: d['src_internal'] = True
            if 'dst_internal' not in d: d['dst_internal'] = True
            
            # Map duration microseconds to ms if it comes from CICIDS flow duration
            if 'duration_ms' in d and isinstance(d['duration_ms'], (int, float)):
                d['duration_ms'] = int(d['duration_ms'] / 1000)
            
            # Translate CICIDS numeric protocol to string
            if 'protocol' in d:
                if d['protocol'] == 6: d['protocol'] = 'TCP'
                elif d['protocol'] == 17: d['protocol'] = 'UDP'
                elif d['protocol'] == 1: d['protocol'] = 'ICMP'
            
            try:
                 events.append(UnifiedEvent(**d))
            except:
                 pass
                 
    except Exception as e:
        print(f"Pandas load failed ({e}), trying standard JSON parser...")
        with open(file_path, "r") as f:
            for line in f:
                if line.strip():
                    events.append(UnifiedEvent.model_validate_json(line))
                    
    return events

def calculate_failed_auth_rate(events: List[UnifiedEvent]) -> Dict[str, float]:
    """Calculate rolling count of 401s in last 60s for each event's src."""
    # Since we need this per event for training, we'll precalculate for all
    # Sort by time just in case
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    
    # Store history of auth failures per source
    auth_failures = defaultdict(list)
    rates = {}
    
    for event in sorted_events:
        src = event.src_entity
        current_time = event.timestamp
        
        if event.layer == "application" and event.status_code == 401:
            auth_failures[src].append(current_time)
            
        # Clean up old failures (> 60s)
        cutoff = current_time - timedelta(seconds=60)
        auth_failures[src] = [t for t in auth_failures[src] if t >= cutoff]
        
        rates[event.event_id] = float(len(auth_failures[src]))
        
    return rates

def extract_features(
    event: UnifiedEvent, 
    if_score: float, 
    baseline_deviation: float,
    profiler: BehavioralBaselineProfiler,
    failed_auth_rate: float
) -> List[float]:
    
    # graph_new_connections (from TM2's graph, pass as param, default 0)
    graph_new_connections = 0.0
    
    # connection_frequency — high during PortScan
    connection_frequency = event.connections_per_minute or 0.0
    
    profile = profiler.profiles.get(event.src_entity)
    
    # bytes_sent_zscore — high during exfiltration
    bytes_sent_zscore = 0.0
    if profile and event.bytes_sent is not None and profile.get("std_bytes_sent", 0) > 0:
        bytes_sent_zscore = abs(event.bytes_sent - profile["avg_bytes_sent"]) / profile["std_bytes_sent"]
    
    # log of bytes_sent — distinguishes large exfil bursts from tiny scan probes
    bytes_sent_log = math.log1p(event.bytes_sent or 0)
    
    # bytes_ratio — exfiltration has very high send vs receive ratio
    bytes_rx = event.bytes_received or 1  # avoid divide-by-zero
    bytes_tx = event.bytes_sent or 0
    bytes_ratio = math.log1p(bytes_tx) / math.log1p(bytes_rx + 1)
    
    # connection_rate_zscore — z-score of conn rate vs entity baseline
    conn_rate_zscore = 0.0
    if profile and profile.get("avg_connections_per_min", 0) is not None:
        avg_conn = profile.get("avg_connections_per_min", 0) or 0.0
        # Use a simple fixed std approximation to avoid div-by-zero on fresh entities
        conn_rate_zscore = min((connection_frequency - avg_conn) / max(avg_conn, 1.0), 10.0)
        
    # dst_port_risk
    dst_port_risk = PORT_RISK.get(event.dst_port, 0.0) if event.dst_port else 0.0
    
    # is_new_destination — 1 if never seen before for this src
    is_new_destination = 1.0
    if profile and event.dst_entity in profile.get("typical_destinations", []):
         is_new_destination = 0.0
         
    # is_external_dst
    is_external_dst = 0.0 if event.dst_internal else 1.0
    
    # hour_of_day cyclical encoding
    hour = event.hour_of_day if event.hour_of_day is not None else event.timestamp.hour
    hour_of_day_sin = math.sin(2 * math.pi * hour / 24.0)
    hour_of_day_cos = math.cos(2 * math.pi * hour / 24.0)
    
    # cross_layer_match (default False — set to 1 if entity flagged in both layers)
    cross_layer_match = 0.0
    
    return [
        if_score,           # IF anomaly score
        baseline_deviation, # entity baseline deviation
        graph_new_connections,
        failed_auth_rate,   # rolling 401 count (brute force signal)
        connection_frequency,      # high during PortScan
        bytes_sent_zscore,  # z-score (exfil vs baseline)
        bytes_sent_log,     # raw log volume (large = exfil)
        bytes_ratio,        # TX/RX ratio (exfil = very high)
        conn_rate_zscore,   # connection rate z-score (PortScan = very high)
        dst_port_risk,
        is_new_destination,
        is_external_dst,
        hour_of_day_sin,
        hour_of_day_cos,
        cross_layer_match
    ]

def train_pipeline():
    # 1. Load data
    events = []
    dataset_dir = Path("datasets")
    
    if dataset_dir.exists():
        print("Scanning real-world CICIDS datasets...")
        for csv_file in dataset_dir.glob("*.csv"):
            print(f"Loading {csv_file.name}...")
            # Load roughly 1k items per file to create a varied dataset
            events.extend(load_flexible_dataset(str(csv_file), max_rows=1000))
    else:
        print("datasets folder not found. Falling back to synthetic.")
        events = load_flexible_dataset("data/raw/combined_labeled.jsonl", max_rows=50000)

    print(f"Loaded a total of {len(events)} events for training.")
    
    if not events:
        print("No events found. Please run data generator first.")
        return

    # 1.5 Extract labels for stratification
    labels = []
    for event in events:
        label = event.attack_type if event.attack_type else "benign"
        if label not in ThreatClassifier.CLASSES:
            label = "benign"
        labels.append(label)

    # 2. Split events directly BEFORE training sub-models (Fixes Data Leakage)
    train_events, test_events, y_train, y_test = train_test_split(
        events, labels, test_size=0.2, stratify=labels, random_state=42
    )
    print(f"Split completed: {len(train_events)} train, {len(test_events)} test")

    # 3. Train Behaviors and IF on TRAIN events only
    profiler = BehavioralBaselineProfiler()
    profiler.build_baselines(train_events)
    print(f"Baselines built for {len(profiler.profiles)} entities")
    profiler.save()

    if_detector = IsolationForestDetector()
    if_detector.fit(train_events)
    if_detector.save()
    print("Isolation Forest trained")

    # Precalculate failed auth rates for feature extraction
    failed_auth_rates_train = calculate_failed_auth_rate(train_events)
    # Testing pre-calc should use test events, though rolling metrics might ideally use history
    failed_auth_rates_test = calculate_failed_auth_rate(test_events)

    # 4. Extract features for RandomForest
    X_train = []
    for event in train_events:
         if_score = if_detector.predict(event)
         baseline_dev = profiler.compute_deviation_score(event)
         auth_rate = failed_auth_rates_train.get(event.event_id, 0.0)
         X_train.append(extract_features(event, if_score, baseline_dev, profiler, auth_rate))

    X_test = []
    for event in test_events:
         if_score = if_detector.predict(event)
         baseline_dev = profiler.compute_deviation_score(event)
         auth_rate = failed_auth_rates_test.get(event.event_id, 0.0)
         X_test.append(extract_features(event, if_score, baseline_dev, profiler, auth_rate))

    X_train = np.array(X_train)
    X_test = np.array(X_test)
    y_train = np.array(y_train)
    y_test = np.array(y_test)

    # 8. Train ThreatClassifier, evaluate, save
    classifier = ThreatClassifier()
    classifier.fit(X_train, y_train)
    
    y_pred = classifier.model.predict(X_test)
    
    # 9. Print final metrics
    test_f1 = f1_score(y_test, y_pred, average="weighted")
    print(f"Threat Classifier — Test F1: {test_f1:.2f}")
    
    classifier.save()
    print("All models saved to data/models/")

def evaluate_pipeline(data_path: str):
    print(f"Loading external dataset from {data_path}...")
    events = load_flexible_dataset(data_path)
    print(f"Loaded {len(events)} events for evaluation")
    
    if not events:
        print("No events found.")
        return

    # Extract labels 
    labels = []
    for event in events:
        label = event.attack_type if event.attack_type else "benign"
        if label not in ThreatClassifier.CLASSES:
            label = "benign"
        labels.append(label)

    # Load trained models
    profiler = BehavioralBaselineProfiler()
    profiler.load()
    
    if_detector = IsolationForestDetector()
    if_detector.load()
    
    classifier = ThreatClassifier()
    classifier.load()
    if not classifier.is_fitted:
        print("Classifier model not found or not trained. Run train pipeline first.")
        return
        
    failed_auth_rates = calculate_failed_auth_rate(events)
    
    X = []
    for event in events:
         if_score = if_detector.predict(event)
         baseline_dev = profiler.compute_deviation_score(event)
         auth_rate = failed_auth_rates.get(event.event_id, 0.0)
         X.append(extract_features(event, if_score, baseline_dev, profiler, auth_rate))

    X = np.array(X)
    
    y_pred = classifier.model.predict(X)
    print("Threat Classifier Evaluation Report:")
    print(classification_report(labels, y_pred, labels=ThreatClassifier.CLASSES))


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "train":
            train_pipeline()
        elif sys.argv[1] == "evaluate" and len(sys.argv) > 2:
            evaluate_pipeline(sys.argv[2])
        else:
            print("Usage: python -m backend.detection.model_trainer [train | evaluate <file_path>]")
    else:
        train_pipeline()
