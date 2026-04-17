import asyncio
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# --- Placeholders for imported modules / components ---
# In reality, these would be imported from your other backend modules.
# e.g., from backend.detection.models import IsolationForestDetector, ThreatClassifier
#       from backend.graph.temporal_kg import TemporalKnowledgeGraph
#       from backend.ingestion.normalizer import NormalizerPipeline
#       from backend.core.websocket_manager import WebSocketManager

class IsolationForestDetector:
    @classmethod
    def load(cls): return cls()
    def predict(self, normalized_event): return 0.0

class ThreatClassifier:
    @classmethod
    def load(cls): return cls()
    def predict(self, features):
        # returns prediction object
        class MockPrediction:
            severity = None
            threat_type = "none"
            confidence = 0.0
        return MockPrediction()

class BehavioralBaselineProfiler:
    @classmethod
    def load(cls): return cls()
    def compute_deviation_score(self, normalized_event): return 0.0

class TemporalKnowledgeGraph:
    def add_event(self, event): pass
    def get_graph_features(self, src_entity): return {}
    def export_cytoscape(self): return {"nodes": [], "edges": []}

class AsyncEventQueue:
    async def consume_batch(self):
        await asyncio.sleep(1)
        return []

class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

class NormalizerPipeline:
    def normalize(self, event_dict):
        # returns an object with attributes
        return None

def build_feature_vector(normalized, if_score, baseline_dev, graph_features):
    return []

# --- Data Models ---
class Alert(BaseModel):
    created_at: float
    threat_type: str
    severity: Optional[str]
    confidence: float
    src_entity: str
    dst_entity: str
    layer: str

# --- 1. App Initialization ---
app = FastAPI(title="AEGIS Threat Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 3. Simulation Worker ---
async def simulation_worker(state):
    while True:
        if not state.simulation_running:
            await asyncio.sleep(0.1)
            continue
            
        batch = await state.event_queue.consume_batch()
        for event in batch:
            state.total_events += 1
            
            # Normalize
            # assuming event is a pydantic model or dict 
            event_dict = event if isinstance(event, dict) else event.dict()
            normalized = NormalizerPipeline().normalize(event_dict)
            
            if not normalized:
                continue
                
            # Update graph
            state.knowledge_graph.add_event(normalized)
            graph_features = state.knowledge_graph.get_graph_features(normalized.src_entity)
            
            # Detection
            if_score = state.if_detector.predict(normalized)
            baseline_dev = state.baseline_profiler.compute_deviation_score(normalized)
            
            # Build feature vector for RF
            features = build_feature_vector(normalized, if_score, baseline_dev, graph_features)
            prediction = state.rf_classifier.predict(features)
            
            if prediction.severity is None:
                continue  # Below alert threshold
                
            # Create alert
            alert = Alert(
                created_at=normalized.timestamp,
                threat_type=prediction.threat_type,
                severity=prediction.severity,
                confidence=prediction.confidence,
                src_entity=normalized.src_entity,
                dst_entity=normalized.dst_entity,
                layer=normalized.layer
            )
            state.alerts.append(alert)
            
            # Broadcast alert via WebSocket
            await state.ws_manager.broadcast({
                "type": "new_alert",
                "data": alert.dict()
            })

# --- 4. Graph Broadcaster ---
async def graph_broadcaster(state):
    while True:
        await asyncio.sleep(2)  # Every 2 seconds
        if state.simulation_running:
            graph_data = state.knowledge_graph.export_cytoscape()
            await state.ws_manager.broadcast({
                "type": "graph_update",
                "data": graph_data
            })

# --- 2. Startup Event ---
@app.on_event("startup")
async def startup():
    # Load all ML models from data/models/
    app.state.if_detector = IsolationForestDetector.load()
    app.state.rf_classifier = ThreatClassifier.load()
    app.state.baseline_profiler = BehavioralBaselineProfiler.load()
    
    app.state.knowledge_graph = TemporalKnowledgeGraph()
    app.state.event_queue = AsyncEventQueue()
    app.state.ws_manager = WebSocketManager()
    
    app.state.incidents = []
    app.state.alerts = []
    app.state.simulation_running = False
    app.state.total_events = 0
    
    # Start background tasks
    asyncio.create_task(simulation_worker(app.state))
    asyncio.create_task(graph_broadcaster(app.state))

# --- 5. REST Routes ---
@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/api/alerts")
def get_alerts():
    return app.state.alerts[-50:]  # last 50

@app.get("/api/incidents")
def get_incidents():
    return app.state.incidents

@app.get("/api/stats/summary")
def get_stats_summary():
    return {
        "total_events": app.state.total_events,
        "total_alerts": len(app.state.alerts),
        "total_incidents": len(app.state.incidents),
        "simulation_running": app.state.simulation_running
    }

@app.post("/api/simulation/start")
def start_simulation():
    app.state.simulation_running = True
    # Start orchestrator if needed
    return {"status": "simulation_started"}

@app.post("/api/simulation/stop")
def stop_simulation():
    app.state.simulation_running = False
    return {"status": "simulation_stopped"}

# --- 6. WebSocket Endpoint ---
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await app.state.ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # Keep alive
    except WebSocketDisconnect:
        app.state.ws_manager.disconnect(websocket)
    except Exception:
        app.state.ws_manager.disconnect(websocket)
