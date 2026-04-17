import networkx as nx
from datetime import datetime, timedelta
from typing import Dict, List

from backend.core.schemas import UnifiedEvent

class TemporalKnowledgeGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.edge_history: Dict[tuple, List[datetime]] = {}

    def add_event(self, event: UnifiedEvent) -> None:
        src = event.src_entity
        dst = event.dst_entity
        now = event.timestamp

        # Add/update source node
        if not self.graph.has_node(src):
            self.graph.add_node(
                src, 
                node_type=self._infer_node_type(src, event), 
                first_seen=now,
                last_seen=now, 
                event_count=0, 
                is_internal=event.src_internal, 
                risk_score=0.0, 
                is_compromised=False 
            )
        self.graph.nodes[src]["last_seen"] = now
        self.graph.nodes[src]["event_count"] += 1

        # Add/update dest node
        if not self.graph.has_node(dst):
            self.graph.add_node(
                dst, 
                node_type=self._infer_node_type(dst, event), 
                first_seen=now, 
                last_seen=now, 
                event_count=0, 
                is_internal=event.dst_internal, 
                risk_score=0.0, 
                is_compromised=False 
            )
        # It's good practice to update destination metrics as well
        self.graph.nodes[dst]["last_seen"] = now
        self.graph.nodes[dst]["event_count"] += 1

        # Add/update edge
        edge_key = (src, dst)
        if self.graph.has_edge(src, dst):
            self.graph.edges[src, dst]["frequency"] += 1
            self.graph.edges[src, dst]["last_seen"] = now
            if event.bytes_sent:
                self.graph.edges[src, dst]["bytes_total"] += event.bytes_sent
        else:
            self.graph.add_edge(
                src, dst, 
                edge_type=self._infer_edge_type(event), 
                first_seen=now, 
                last_seen=now, 
                frequency=1, 
                bytes_total=event.bytes_sent or 0,
                layer=event.layer, 
                is_anomalous=False 
            )
        self.edge_history.setdefault(edge_key, []).append(now)

    def get_new_connections(self, entity: str, since_minutes: int = 10) -> List[str]:
        """Return destinations this entity connected to for the first time recently."""
        cutoff = datetime.now() - timedelta(minutes=since_minutes)
        new_conns = []
        for src, dst, data in self.graph.edges(entity, data=True):
            if data["first_seen"] >= cutoff and data["frequency"] == 1:
                new_conns.append(dst)
        return new_conns

    def get_graph_features(self, entity: str) -> Dict[str, float]:
        """Compute graph-based features for detection engine."""
        if not self.graph.has_node(entity):
            return {"degree": 0, "new_connections": 0, "external_ratio": 0.0, "total_bytes": 0.0}
            
        neighbors = list(self.graph.successors(entity))
        external = [n for n in neighbors if not self.graph.nodes[n].get("is_internal", True)]
        
        # Calculate total bytes using comprehension sum
        total_bytes = sum(self.graph.edges[entity, n].get("bytes_total", 0) for n in neighbors if self.graph.has_edge(entity, n))
        
        return {
            "degree": self.graph.out_degree(entity),
            "new_connections": len(self.get_new_connections(entity)),
            "external_ratio": len(external) / max(len(neighbors), 1),
            "total_bytes": float(total_bytes)
        }

    def mark_compromised(self, entity: str) -> None:
        if self.graph.has_node(entity):
            self.graph.nodes[entity]["is_compromised"] = True
            self.graph.nodes[entity]["risk_score"] = 1.0

    def update_risk_score(self, entity: str, score: float) -> None:
        if self.graph.has_node(entity):
            current = self.graph.nodes[entity]["risk_score"]
            # Exponential moving average — risk only goes up
            self.graph.nodes[entity]["risk_score"] = max(current, score)

    def _infer_node_type(self, entity: str, event: UnifiedEvent) -> str:
        if entity.startswith("10.") or entity[0].isdigit():
            return "ip"
        if "@" in entity or event.layer == "application":
            return "user"
        if ".exe" in entity.lower():
            return "process"
        return "host"

    def _infer_edge_type(self, event: UnifiedEvent) -> str:
        if event.layer == "network":
            return "connects_to"
        if event.action == "exec":
            return "executes"
        if event.action in ["read", "write"]:
            return event.action + "s"
        return "interacts_with"

    def export_cytoscape(self) -> dict:
        """Export graph in Cytoscape.js format for frontend."""
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            nodes.append({
                "data": {
                    "id": node_id,
                    "label": node_id[-15:] if len(node_id) > 15 else node_id,
                    "type": data.get("node_type", "host"),
                    "risk_score": round(data.get("risk_score", 0.0), 2),
                    "is_compromised": data.get("is_compromised", False),
                    "event_count": data.get("event_count", 0),
                    "is_internal": data.get("is_internal", True)
                }
            })
            
        edges = []
        for src, dst, data in self.graph.edges(data=True):
            edges.append({
                "data": {
                    "id": f"{src}_{dst}",
                    "source": src,
                    "target": dst,
                    "edge_type": data.get("edge_type"),
                    "frequency": data.get("frequency", 1),
                    "is_anomalous": data.get("is_anomalous", False),
                    "bytes_total": data.get("bytes_total", 0)
                }
            })
            
        return {"nodes": nodes, "edges": edges}
