from pydantic import BaseModel, Field
from typing import Optional, Literal, List, Dict, Any
from datetime import datetime
import uuid

class UnifiedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    layer: Literal["network", "endpoint", "application"]
    src_entity: str
    dst_entity: str
    src_internal: bool
    dst_internal: bool

    # Network fields
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    duration_ms: Optional[int] = None
    tcp_flags: Optional[str] = None

    # Endpoint fields
    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    user_account: Optional[str] = None
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    file_path: Optional[str] = None
    action: Optional[str] = None

    # Application fields
    http_method: Optional[str] = None
    endpoint_path: Optional[str] = None
    status_code: Optional[int] = None
    payload_size_bytes: Optional[int] = None
    user_agent: Optional[str] = None
    geo_country: Optional[str] = None
    auth_result: Optional[str] = None

    # Computed at normalization
    hour_of_day: Optional[int] = None
    is_business_hours: Optional[bool] = None
    bytes_ratio: Optional[float] = None
    port_risk_score: Optional[float] = None
    connections_per_minute: Optional[float] = None

    # Training labels (None in demo mode)
    raw_label: Optional[str] = None
    attack_type: Optional[str] = None


class DetectionResult(BaseModel):
    event_id: str
    timestamp: datetime
    layer: str
    src_entity: str
    dst_entity: str
    if_score: float = 0.0
    baseline_deviation: float = 0.0
    graph_score: float = 0.0
    threat_type: Optional[str] = None
    confidence: float = 0.0
    severity: Optional[str] = None
    is_alert: bool = False


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime
    threat_type: str
    severity: str
    confidence: float
    src_entity: str
    dst_entity: str
    layer: str
    layers_involved: List[str] = []
    explanation: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    is_false_positive: bool = False
    fp_reason: Optional[str] = None
    raw_detection: Optional[Dict] = None


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime
    updated_at: datetime
    status: Literal["open", "investigating", "resolved"] = "open"
    threat_type: str
    severity: str
    confidence: float
    is_false_positive: bool = False
    fp_reason: Optional[str] = None
    affected_entities: List[str] = []
    layers_involved: List[str] = []
    alert_ids: List[str] = []
    explanation: Optional[str] = None
    mitre_techniques: List[Dict] = []
    current_kill_chain_stage: Optional[str] = None
    predicted_next_stage: Optional[str] = None
    playbook: Optional[Dict] = None
