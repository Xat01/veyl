"""Attack-surface graph construction.

The graph is materialised rather than computed per request, so it is queryable,
so historical graphs remain reconstructable, and so a report can reference a
node that still exists.

Node identity is a stable string key (``type:identifier``) rather than a row id,
which means the graph rebuild is idempotent: running it twice produces the same
nodes and the same edges.

Structure produced for a typical asset::

    Organization
      └─ OWNS ─> Asset (api.acmepay.example)
                   ├─ RESOLVES_TO ─> IP
                   ├─ EXPOSES ─────> Port 443
                   │                  └─ RUNS ──> Service (https)
                   │                                └─ SERVES ─> Application
                   │                                              └─ SERVES ─> API
                   ├─ BELONGS_TO ──> BusinessFunction (PAYMENTS)
                   ├─ AFFECTED_BY ─> Finding
                   └─ CHANGED_TO ──> ExposureChange
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from veyl_api.db.base import utcnow
from veyl_api.enums import (
    ACTIVE_FINDING_STATUSES,
    AssetType,
    EdgeType,
    NodeType,
)
from veyl_api.models import (
    Asset,
    Certificate,
    ExposureChange,
    Finding,
    GraphEdge,
    GraphNode,
    Observation,
    Organization,
    Scan,
    Service,
)


def node_key(node_type: NodeType, identifier: str) -> str:
    """Canonical, stable graph node key."""
    return f"{node_type.value}:{identifier}"[:300]


@dataclass
class GraphPayload:
    """Serialised graph for the API and the UI."""

    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


def rebuild_graph(session: Session, *, organization_id: str) -> GraphPayload:
    """Rebuild the graph for one organization from current database state.

    Idempotent: existing nodes and edges for the tenant are replaced. Only current
    state is represented; history lives in scans, snapshots and changes.
    """
    now = utcnow()

    organization = session.get(Organization, organization_id)
    if organization is None:
        return GraphPayload()

    # Clear first so removals propagate. Edges are deleted before nodes to
    # respect the natural dependency order.
    session.execute(delete(GraphEdge).where(GraphEdge.organization_id == organization_id))
    session.execute(delete(GraphNode).where(GraphNode.organization_id == organization_id))
    session.flush()

    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str, str], GraphEdge] = {}

    def add_node(
        node_type: NodeType,
        identifier: str,
        label: str,
        *,
        ref_id: str | None = None,
        properties: dict[str, Any] | None = None,
        risk_score: float = 0.0,
    ) -> str:
        key = node_key(node_type, identifier)
        if key in nodes:
            return key
        node = GraphNode(
            organization_id=organization_id,
            node_key=key,
            node_type=node_type.value,
            label=label[:300],
            ref_id=ref_id,
            properties=properties or {},
            risk_score=risk_score,
            first_seen=now,
            last_seen=now,
        )
        nodes[key] = node
        return key

    def add_edge(
        source: str, target: str, edge_type: EdgeType, properties: dict[str, Any] | None = None
    ) -> None:
        composite = (source, target, edge_type.value)
        if composite in edges:
            return
        edges[composite] = GraphEdge(
            organization_id=organization_id,
            source_key=source,
            target_key=target,
            edge_type=edge_type.value,
            properties=properties or {},
        )

    org_key = add_node(
        NodeType.ORGANIZATION,
        organization.id,
        organization.name,
        ref_id=organization.id,
        properties={
            "slug": organization.slug,
            "primary_domain": organization.primary_domain,
            "industry": organization.industry,
        },
    )

    assets = list(
        session.execute(
            select(Asset).where(
                Asset.organization_id == organization_id,
                Asset.status == "ACTIVE",
            )
        ).scalars()
    )
    asset_keys: dict[str, str] = {}

    for asset in assets:
        key = add_node(
            NodeType.ASSET,
            asset.id,
            asset.asset_key,
            ref_id=asset.id,
            properties={
                "asset_key": asset.asset_key,
                "asset_type": asset.asset_type.value,
                "environment": asset.environment.value,
                "internet_exposed": asset.internet_exposed,
                "business_criticality": asset.business_criticality.value,
                "data_classification": asset.data_classification.value,
                "owner": asset.owner.value,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
            },
            risk_score=0.0,
        )
        asset_keys[asset.id] = key
        add_edge(org_key, key, EdgeType.OWNS)

        # Domain node, when the asset is a name rather than an address.
        if asset.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN) and asset.hostname:
            domain_key = add_node(
                NodeType.DOMAIN,
                asset.hostname,
                asset.hostname,
                ref_id=asset.id,
                properties={"asset_type": asset.asset_type.value},
            )
            add_edge(domain_key, key, EdgeType.OWNS)

        # IP node.
        if asset.ip_address:
            ip_key = add_node(
                NodeType.IP,
                asset.ip_address,
                asset.ip_address,
                properties={"address": asset.ip_address},
            )
            add_edge(key, ip_key, EdgeType.RESOLVES_TO)

        # Business function node.
        function_key = add_node(
            NodeType.BUSINESS_FUNCTION,
            asset.business_function.value,
            asset.business_function.value.replace("_", " ").title(),
            properties={"function": asset.business_function.value},
        )
        add_edge(key, function_key, EdgeType.BELONGS_TO)

        # Services and ports.
        services = list(
            session.execute(
                select(Service).where(Service.asset_id == asset.id)
            ).scalars()
        )
        for service in services:
            port_key = add_node(
                NodeType.PORT,
                f"{asset.id}:{service.port}/{service.protocol}",
                f"{service.port}/{service.protocol}",
                properties={
                    "port": service.port,
                    "protocol": service.protocol,
                    "state": service.state,
                    "asset_key": asset.asset_key,
                },
            )
            add_edge(key, port_key, EdgeType.EXPOSES, {"port": service.port})

            if service.service_name and service.service_name != "unknown":
                service_key = add_node(
                    NodeType.SERVICE,
                    f"{service.service_name}:{asset.id}:{service.port}",
                    (
                        f"{service.service_name}"
                        + (f" {service.product}" if service.product else "")
                        + (f" {service.version}" if service.version else "")
                    ),
                    properties={
                        "service_name": service.service_name,
                        "product": service.product,
                        "version": service.version,
                        "confidence": service.fingerprint_confidence.value,
                        "port": service.port,
                        "is_encrypted": service.is_encrypted,
                        "is_administrative": service.is_administrative,
                        "is_database": service.is_database,
                        "fingerprint_evidence": service.fingerprint_evidence,
                    },
                )
                add_edge(port_key, service_key, EdgeType.RUNS)

                # Application layer for web-facing services.
                if service.service_name in ("http", "https"):
                    app_key = add_node(
                        NodeType.APPLICATION,
                        f"app:{asset.id}:{service.port}",
                        f"{asset.asset_key} application",
                        properties={
                            "port": service.port,
                            "scheme": service.service_name,
                            "tls": service.is_encrypted,
                        },
                    )
                    add_edge(service_key, app_key, EdgeType.SERVES)

                    # API node, when API evidence exists for this asset.
                    api_evidence = session.execute(
                        select(Observation)
                        .where(
                            Observation.organization_id == organization_id,
                            Observation.asset_id == asset.id,
                            Observation.kind == "http_discovery_path",
                        )
                        .limit(50)
                    ).scalars()
                    api_paths = [
                        o.data.get("path")
                        for o in api_evidence
                        if o.data.get("path") in
                        ("/openapi.json", "/swagger.json", "/api-docs", "/swagger-ui.html",
                         "/swagger/index.html", "/.well-known/openid-configuration")
                        and o.data.get("status_code") == 200
                    ]
                    if api_paths:
                        api_key = add_node(
                            NodeType.API,
                            f"api:{asset.id}",
                            f"{asset.asset_key} API",
                            properties={
                                "asset_key": asset.asset_key,
                                "documentation_paths": api_paths,
                                "documented": True,
                            },
                        )
                        add_edge(app_key, api_key, EdgeType.SERVES)

        # Certificate node.
        certificates = list(
            session.execute(
                select(Certificate).where(Certificate.asset_id == asset.id)
            ).scalars()
        )
        for certificate in certificates[:5]:
            cert_key = add_node(
                NodeType.CERTIFICATE,
                certificate.id,
                f"cert {certificate.subject}"[:120],
                ref_id=certificate.id,
                properties={
                    "subject": certificate.subject,
                    "issuer": certificate.issuer,
                    "not_after": certificate.not_after.isoformat(),
                    "days_remaining": certificate.days_remaining,
                    "is_self_signed": certificate.is_self_signed,
                    "tls_version": certificate.tls_version,
                    "fingerprint_sha256": certificate.fingerprint_sha256,
                },
            )
            add_edge(key, cert_key, EdgeType.DEPENDS_ON)

    # Findings.
    findings = list(
        session.execute(
            select(Finding).where(
                Finding.organization_id == organization_id,
                Finding.status.in_([s.value for s in ACTIVE_FINDING_STATUSES]),
            )
        ).scalars()
    )
    asset_risk: dict[str, float] = defaultdict(float)
    for finding in findings:
        asset_row = session.get(Asset, finding.asset_id)
        finding_key = add_node(
            NodeType.FINDING,
            finding.id,
            f"[{finding.severity.value}] {finding.title}"[:200],
            ref_id=finding.id,
            properties={
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "status": finding.status.value,
                "risk_score": finding.risk_score,
                "asset_key": asset_row.asset_key if asset_row else None,
                "evidence_count": len(finding.evidence) if finding.evidence else 0,
            },
            risk_score=finding.risk_score,
        )
        target_asset_key = asset_keys.get(finding.asset_id)
        if target_asset_key:
            add_edge(target_asset_key, finding_key, EdgeType.AFFECTED_BY)
            asset_risk[target_asset_key] = max(
                asset_risk[target_asset_key], finding.risk_score
            )

    # Exposure changes from the most recent scan.
    latest_scan = session.execute(
        select(Scan)
        .where(Scan.organization_id == organization_id, Scan.status == "COMPLETED")
        .order_by(Scan.finished_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    recent_change_types: dict[str, set[str]] = defaultdict(set)
    if latest_scan is not None:
        changes = list(
            session.execute(
                select(ExposureChange).where(
                    ExposureChange.organization_id == organization_id,
                    ExposureChange.scan_id == latest_scan.id,
                )
            ).scalars()
        )
        for change in changes:
            if change.asset_id is None:
                continue
            source_key = asset_keys.get(change.asset_id)
            if source_key is None:
                continue
            change_key = add_node(
                NodeType.ASSET,
                f"change:{change.id}",
                f"{change.change_type.value} on {change.subject}"[:200],
                ref_id=change.id,
                properties={
                    "change_type": change.change_type.value,
                    "significance": change.significance.value,
                    "subject": change.subject,
                    "previous_state": change.previous_state,
                    "current_state": change.current_state,
                    "is_risk_increasing": change.is_risk_increasing,
                    "risk_score": change.risk_score,
                },
                risk_score=change.risk_score,
            )
            add_edge(source_key, change_key, EdgeType.CHANGED_TO)
            recent_change_types[source_key].add(change.change_type.value)

    # Apply the risk score computed from findings to asset nodes.
    for key, score in asset_risk.items():
        if key in nodes:
            nodes[key].risk_score = round(min(score, 100.0), 1)

    for node in nodes.values():
        session.add(node)
    session.flush()
    for edge in edges.values():
        session.add(edge)
    session.flush()

    return GraphPayload(
        nodes=[
            {
                "key": n.node_key,
                "type": n.node_type,
                "label": n.label,
                "ref_id": n.ref_id,
                "properties": n.properties,
                "risk_score": n.risk_score,
            }
            for n in nodes.values()
        ],
        edges=[
            {
                "source": e.source_key,
                "target": e.target_key,
                "type": e.edge_type,
                "properties": e.properties,
            }
            for e in edges.values()
        ],
        stats={
            "nodes": len(nodes),
            "edges": len(edges),
            "assets": len(assets),
            "services": sum(1 for n in nodes.values() if n.node_type == NodeType.SERVICE.value),
            "findings": len(findings),
            "recent_changes": sum(len(v) for v in recent_change_types.values()),
        },
    )


def load_graph(
    session: Session,
    *,
    organization_id: str,
    node_types: list[str] | None = None,
    max_nodes: int = 2000,
) -> GraphPayload:
    """Read the materialised graph for one tenant."""
    node_query = select(GraphNode).where(GraphNode.organization_id == organization_id)
    if node_types:
        node_query = node_query.where(GraphNode.node_type.in_(node_types))
    node_query = node_query.order_by(GraphNode.risk_score.desc()).limit(max_nodes)

    nodes = list(session.execute(node_query).scalars())
    keys = {n.node_key for n in nodes}

    edge_query = select(GraphEdge).where(GraphEdge.organization_id == organization_id)
    edges = [
        e
        for e in session.execute(edge_query).scalars()
        if e.source_key in keys and e.target_key in keys
    ]

    return GraphPayload(
        nodes=[
            {
                "key": n.node_key,
                "type": n.node_type,
                "label": n.label,
                "ref_id": n.ref_id,
                "properties": n.properties,
                "risk_score": n.risk_score,
            }
            for n in nodes
        ],
        edges=[
            {
                "source": e.source_key,
                "target": e.target_key,
                "type": e.edge_type,
                "properties": e.properties,
            }
            for e in edges
        ],
        stats={"nodes": len(nodes), "edges": len(edges)},
    )


def neighbours(
    session: Session, *, organization_id: str, node_key_value: str, depth: int = 1
) -> GraphPayload:
    """Return the subgraph within ``depth`` hops of a node."""
    all_nodes = {
        n.node_key: n
        for n in session.execute(
            select(GraphNode).where(GraphNode.organization_id == organization_id)
        ).scalars()
    }
    all_edges = list(
        session.execute(
            select(GraphEdge).where(GraphEdge.organization_id == organization_id)
        ).scalars()
    )

    adjacency: dict[str, list[GraphEdge]] = defaultdict(list)
    for edge in all_edges:
        adjacency[edge.source_key].append(edge)
        adjacency[edge.target_key].append(edge)

    visited = {node_key_value}
    frontier = {node_key_value}
    for _ in range(max(0, depth)):
        next_frontier: set[str] = set()
        for key in frontier:
            for edge in adjacency.get(key, []):
                other = edge.target_key if edge.source_key == key else edge.source_key
                if other not in visited:
                    visited.add(other)
                    next_frontier.add(other)
        frontier = next_frontier
        if not frontier:
            break

    # Keep neighbour discovery focused on nodes that actually exist in the store.
    visited &= set(all_nodes.keys())

    return GraphPayload(
        nodes=[
            {
                "key": all_nodes[key].node_key,
                "type": all_nodes[key].node_type,
                "label": all_nodes[key].label,
                "ref_id": all_nodes[key].ref_id,
                "properties": all_nodes[key].properties,
                "risk_score": all_nodes[key].risk_score,
            }
            for key in sorted(visited)
            if key in all_nodes
        ],
        edges=[
            {
                "source": e.source_key,
                "target": e.target_key,
                "type": e.edge_type,
                "properties": e.properties,
            }
            for e in all_edges
            if e.source_key in visited and e.target_key in visited
        ],
        stats={"nodes": len(visited), "edges": 0, "centre": node_key_value, "depth": depth},
    )
