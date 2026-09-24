"""Attack-surface graph endpoint.

The graph is materialised rather than computed per request, so it can be
paginated and so a historical graph stays reconstructable. Nodes carry a stable
``node_key`` of the form ``type:identifier``, which is what edges reference —
never a row id, so a rebuilt graph reconnects itself.
"""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import func, select

from veyl_api.api.deps import DbSession, require
from veyl_api.api.schemas import GraphEdgeOut, GraphNodeOut, GraphOut
from veyl_api.models import GraphEdge, GraphNode

router = APIRouter()


@router.get("", response_model=GraphOut, summary="Fetch the attack-surface graph")
def get_graph(
    session: DbSession,
    context=require("graph:read"),
    node_type: str | None = None,
    min_risk: float | None = None,
    max_nodes: int = 500,
    max_edges: int = 2000,
) -> GraphOut:
    """Return nodes and edges for the organization.

    ``max_nodes`` is capped rather than unbounded because a graph view that
    tries to render a hundred thousand nodes is unusable, and the API should not
    be the thing that discovers that.
    """
    max_nodes = max(1, min(max_nodes, 2000))
    max_edges = max(1, min(max_edges, 10000))

    node_conditions = [GraphNode.organization_id == context.organization.id]
    if node_type:
        node_conditions.append(GraphNode.node_type == node_type)
    if min_risk is not None:
        node_conditions.append(GraphNode.risk_score >= min_risk)

    total_nodes = session.execute(
        select(func.count()).select_from(GraphNode).where(*node_conditions)
    ).scalar_one()

    nodes = list(
        session.execute(
            select(GraphNode)
            .where(*node_conditions)
            .order_by(GraphNode.risk_score.desc())
            .limit(max_nodes)
        ).scalars()
    )
    node_keys = {n.node_key for n in nodes}

    edge_conditions = [GraphEdge.organization_id == context.organization.id]
    total_edges = session.execute(
        select(func.count()).select_from(GraphEdge).where(*edge_conditions)
    ).scalar_one()

    edges = list(
        session.execute(
            select(GraphEdge)
            .where(*edge_conditions)
            .order_by(GraphEdge.risk_score.desc())
            .limit(max_edges)
        ).scalars()
    )

    return GraphOut(
        nodes=[
            GraphNodeOut(
                id=n.id,
                node_key=n.node_key,
                node_type=n.node_type,
                label=n.label,
                ref_id=n.ref_id,
                properties=dict(n.properties or {}),
                risk_score=n.risk_score,
            )
            for n in nodes
        ],
        edges=[
            GraphEdgeOut(
                id=e.id,
                source_key=e.source_key,
                target_key=e.target_key,
                edge_type=e.edge_type,
                properties=dict(e.properties or {}),
                risk_score=e.risk_score,
            )
            # Only edges whose endpoints survived the node limit: an edge to an
            # absent node would render as a dangling line.
            for e in edges
            if e.source_key in node_keys and e.target_key in node_keys
        ],
        node_count=total_nodes,
        edge_count=total_edges,
    )


@router.post("/rebuild", response_model=GraphOut, summary="Rebuild the graph from current data")
def rebuild_graph(session: DbSession, context=require("asset:write")) -> GraphOut:
    """Regenerate the graph from assets, services, findings, and certificates.

    Idempotent: running it twice produces the same graph, because nodes are keyed
    by identity rather than by insertion order.
    """
    from veyl_api.audit import AuditRecord, write_audit
    from veyl_api.enums import AuditAction
    from veyl_correlation import rebuild_graph as _rebuild

    stats = _rebuild(session, organization_id=context.organization.id)
    write_audit(
        session,
        AuditRecord(
            action=AuditAction.GRAPH_REBUILT,
            organization_id=context.organization.id,
            actor_user_id=context.user.id,
            actor_email=context.user.email,
            actor_role=context.role.value,
            resource_type="graph",
            resource_id=context.organization.id,
            detail=f"{len(stats.nodes)} node(s), {len(stats.edges)} edge(s)",
        ),
    )
    session.commit()
    return get_graph(session=session, context=context)
