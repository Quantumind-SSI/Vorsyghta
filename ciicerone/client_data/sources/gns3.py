"""GNS3 topology file adapter."""

import json
from pathlib import Path
from typing import Any, Dict, List

from ciicerone.client_data.config import ClientDataSourceConfig
from ciicerone.client_data.credentials import CredentialProvider
from ciicerone.client_data.models import (
    Asset,
    ClientProfile,
    NetworkLink,
    NetworkNode,
    NetworkTopology,
)
from .base import ClientDataSource


class Gns3Source(ClientDataSource):
    """Parse GNS3 .gns3 project files into network topology and assets."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.project_path = Path(self.config.settings.get("project_path", ""))

    async def authenticate(self) -> bool:
        return self.project_path.exists() and self.project_path.suffix == ".gns3"

    async def fetch(self) -> ClientProfile:
        with open(self.project_path, "r") as f:
            raw = json.load(f)
        return self.normalize(raw)

    def normalize(self, raw_data: Any) -> ClientProfile:
        topology = raw_data.get("topology", {})
        nodes = self._parse_nodes(topology.get("nodes", []))
        links = self._parse_links(topology.get("links", []), nodes)
        subnets = self._extract_subnets(topology.get("nodes", []))
        network = NetworkTopology(
            name=raw_data.get("name", "GNS3 Topology"),
            nodes=nodes,
            links=links,
            subnets=subnets,
            metadata={"version": raw_data.get("version", "unknown")},
        )
        return ClientProfile(
            tenant_id=self.config.tenant_id,
            network_topology=network,
            assets=self._nodes_to_assets(nodes),
        )

    def _parse_nodes(self, raw_nodes: List[Dict[str, Any]]) -> List[NetworkNode]:
        return [
            NetworkNode(
                node_id=node.get("node_id", node.get("id", "")),
                name=node.get("name", ""),
                node_type=node.get("node_type", "unknown"),
                properties={
                    "console": node.get("console"),
                    "console_type": node.get("console_type"),
                    "symbol": node.get("symbol"),
                    "port_name_format": node.get("port_name_format"),
                    "first_port_name": node.get("first_port_name"),
                },
            )
            for node in raw_nodes
        ]

    def _parse_links(
        self,
        raw_links: List[Dict[str, Any]],
        nodes: List[NetworkNode],
    ) -> List[NetworkLink]:
        result = []
        node_id_map = {n.node_id: n.id for n in nodes}
        for link in raw_links:
            link_nodes = link.get("nodes", [])
            if len(link_nodes) >= 2:
                source_id = node_id_map.get(link_nodes[0].get("node_id", ""))
                target_id = node_id_map.get(link_nodes[1].get("node_id", ""))
                if source_id and target_id:
                    result.append(
                        NetworkLink(
                            source_id=source_id,
                            target_id=target_id,
                            link_type=link.get("link_type", "ethernet"),
                            properties={
                                "link_id": link.get("link_id", ""),
                                "filters": link.get("filters", {}),
                            },
                        )
                    )
        return result

    def _extract_subnets(self, raw_nodes: List[Dict[str, Any]]) -> List[str]:
        subnets = set()
        for node in raw_nodes:
            for prop in ["properties", "custom_adapters"]:
                data = node.get(prop, {})
                if isinstance(data, dict):
                    ip = data.get("ip_address") or data.get("ip")
                    if ip and "/" in ip:
                        subnets.add(ip)
        return sorted(subnets)

    def _nodes_to_assets(self, nodes: List[NetworkNode]) -> List[Asset]:
        return [
            Asset(
                source_id=n.node_id,
                name=n.name,
                asset_type=n.node_type,
                metadata=n.properties,
            )
            for n in nodes
        ]
