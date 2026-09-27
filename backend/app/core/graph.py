import networkx as nx
from typing import Dict, List, Any

class DependencyGraph:
    def __init__(self, services: List[Dict[str, Any]], assets: List[Dict[str, Any]]):
        self.services = {(s.get("id") or s.get("service_id")): s for s in services}
        self.assets = {(a.get("id") or a.get("asset_id")): a for a in assets}
        self.graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self):
        # Add services
        for s_id, s in self.services.items():
            self.graph.add_node(s_id, type="service", name=s["name"], revenue_per_hour=s.get("revenue_per_hour", 0.0))
            for dep in s.get("depends_on", []):
                self.graph.add_edge(dep, s_id, type="service_dependency")

        # Add assets and link to their primary business services
        for a_id, a in self.assets.items():
            self.graph.add_node(
                a_id,
                type="asset",
                name=a["name"],
                revenue_per_hour=a.get("revenue_per_hour", 0.0),
                criticality=a.get("criticality_1_5", 3),
                internet_facing=a.get("internet_facing", False)
            )
            svc_id = a.get("business_service_id")
            if svc_id and svc_id in self.services:
                self.graph.add_edge(a_id, svc_id, type="supports_service")

    def get_dependent_services(self, asset_id: str) -> List[str]:
        """Finds all business services reachable downstream from this asset."""
        if asset_id not in self.graph:
            return []
        descendants = nx.descendants(self.graph, asset_id)
        return [node for node in descendants if self.graph.nodes[node].get("type") == "service"]

    def compute_asset_effective_revenue_impact(self, asset_id: str) -> float:
        """impact(a) = own_revenue(a) + sum_{services depending on a} service_revenue"""
        if asset_id not in self.graph:
            return 0.0
        own_rev = self.graph.nodes[asset_id].get("revenue_per_hour", 0.0)
        dep_services = self.get_dependent_services(asset_id)
        dep_rev = sum(self.services[s_id].get("revenue_per_hour", 0.0) for s_id in dep_services if s_id in self.services)
        return own_rev + dep_rev

    def identify_choke_points(self, top_n: int = 5) -> List[Dict[str, Any]]:
        """Identifies choke-point assets with high betweenness centrality or high dependent count."""
        asset_nodes = [n for n, d in self.graph.nodes(data=True) if d.get("type") == "asset"]
        if not asset_nodes:
            return []

        # Betweenness centrality
        try:
            centrality = nx.betweenness_centrality(self.graph)
        except Exception:
            centrality = {n: 0.0 for n in self.graph.nodes()}

        choke_points = []
        for a_id in asset_nodes:
            dep_svcs = self.get_dependent_services(a_id)
            total_impact = self.compute_asset_effective_revenue_impact(a_id)
            asset_info = self.assets[a_id]
            choke_points.append({
                "asset_id": a_id,
                "asset_name": asset_info["name"],
                "dependent_service_count": len(dep_svcs),
                "dependent_services": [self.services[s]["name"] for s in dep_svcs if s in self.services],
                "effective_revenue_per_hour": total_impact,
                "betweenness_score": round(centrality.get(a_id, 0.0), 4),
                "criticality": asset_info.get("criticality_1_5", 3),
                "internet_facing": asset_info.get("internet_facing", False)
            })

        # Sort by dependent service count, then effective revenue, then betweenness
        choke_points.sort(key=lambda x: (x["dependent_service_count"], x["effective_revenue_per_hour"], x["betweenness_score"]), reverse=True)
        return choke_points[:top_n]
