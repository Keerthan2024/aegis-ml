# All shared constants — teammates import from here, never hardcode values
INTERNAL_IP_RANGE = "10.0.0.0/8"
INTERNAL_IPS = [f"10.0.0.{i}" for i in range(1, 101)]

# Detection thresholds
ANOMALY_THRESHOLD = 0.65  # IF score above this = anomalous
CONFIDENCE_ALERT_MIN = 0.40  # Don't create alert below this confidence
CONFIDENCE_CRITICAL = 0.90
CONFIDENCE_HIGH = 0.75
CONFIDENCE_MEDIUM = 0.50

# Queue settings
QUEUE_MAX_SIZE = 10000
BATCH_SIZE = 50
TARGET_EVENTS_PER_SEC = 500

# Simulation settings
SIMULATION_DURATION_SEC = 600  # 10 minutes

# Port risk scores
PORT_RISK = {
    22: 0.6,
    23: 0.9,
    445: 0.7,
    3389: 0.8,
    4444: 1.0,
    8080: 0.5,
    443: 0.1,
    80: 0.1,
    53: 0.0
}

# Known malicious process names
MALICIOUS_PROCESSES = [
    "psexec.exe",
    "mimikatz.exe",
    "cobalt_strike.exe",
    "meterpreter.exe",
    "nc.exe",
    "nmap.exe"
]

# Attack scenario IPs
ATTACKER_IPS = ["185.220.101.45", "185.220.101.46", "185.220.101.47"]
C2_SERVER_IP = "203.0.113.45"
C2_PORT = 8080

# Model file paths
MODEL_DIR = "data/models"
IF_NETWORK_PATH = f"{MODEL_DIR}/isolation_forest_network.pkl"
IF_ENDPOINT_PATH = f"{MODEL_DIR}/isolation_forest_endpoint.pkl"
RF_CLASSIFIER_PATH = f"{MODEL_DIR}/threat_classifier.pkl"
BASELINES_PATH = f"{MODEL_DIR}/entity_baselines.pkl"
