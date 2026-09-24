"""Detection rule framework.

A rule is a pure function from observations to findings. It has no network
access, no database access beyond what the evaluator hands it, and no ability to
invent evidence: the contract requires every finding to cite at least one
observation it actually read.

That constraint is what makes the whole product defensible. If a rule cannot
point at an observation, it cannot raise a finding.

Structure of a rule::

    RuleDefinition(
        rule_id="VEYL-WEB-001",
        title="Missing HTTP Strict Transport Security",
        category=RuleCategory.WEB,
        severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        description="...",
        detection="...",
        evidence_requirements=["http_security_headers"],
        remediation="...",
        check=check_missing_hsts,
        references=[...],
    )
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from veyl_api.enums import Confidence, RuleCategory, Severity

#: A subject is the normalized view of one asset for one scan.
ObservationData = dict[str, Any]


@dataclass
class RuleContext:
    """Everything a rule is allowed to see.

    Deliberately narrow. A rule gets the observations for a single asset from a
    single scan, plus a little derived context. It cannot query the database,
    make network calls, or see other tenants.
    """

    #: Observation payloads keyed by ``kind``. Multiple observations of the same
    #: kind are kept in order.
    by_kind: dict[str, list[ObservationData]] = field(default_factory=dict)

    #: Business context, used only for wording — never to invent evidence.
    business_criticality: str = "LOW"
    data_classification: str = "PUBLIC"
    environment: str = "UNKNOWN"
    business_function: str = "OTHER"
    internet_exposed: bool = False

    asset_key: str = ""
    hostname: str | None = None

    def of_kind(self, kind: str) -> list[ObservationData]:
        return self.by_kind.get(kind, [])

    def first(self, kind: str) -> ObservationData | None:
        values = self.by_kind.get(kind)
        return values[0] if values else None

    def has_kind(self, kind: str) -> bool:
        return bool(self.by_kind.get(kind))

    def subjects(self, kind: str) -> list[str]:
        return [str(o.get("subject", "")) for o in self.of_kind(kind)]


@dataclass
class RuleMatch:
    """One violation produced by a rule.

    ``evidence`` must reference observations that exist in the context. The
    evaluator verifies this and rejects matches that cite nothing.
    """

    #: Distinguishes multiple matches from the same rule on one asset,
    #: e.g. port 443 vs port 8443. Becomes part of the finding's dedup key.
    subject_suffix: str = ""

    #: Short, factual statement of what was observed.
    summary: str = ""

    #: Why the rule fired, in terms of the evidence, not in terms of impact.
    detection_explanation: str = ""

    #: What could go wrong. Written carefully, without exaggeration.
    impact: str = ""

    #: Machine-readable evidence references. Each entry names the observation
    #: kind and the specific values that were relied upon.
    evidence: list[dict[str, Any]] = field(default_factory=list)

    #: Optional per-match overrides.
    severity: Severity | None = None
    confidence: Confidence | None = None

    #: Optional CVEs. Only ever populated from a provider lookup that matched
    #: both product and version. A rule that cannot prove a version must leave
    #: this empty.
    vulnerability_refs: list[dict[str, Any]] = field(default_factory=list)

    #: Extra risk factors this match contributes beyond the base scoring.
    risk_factors: dict[str, Any] = field(default_factory=dict)


RuleCheck = Callable[[RuleContext], list[RuleMatch]]


@dataclass
class RuleDefinition:
    """A deterministic detection rule."""

    rule_id: str
    title: str
    category: RuleCategory
    severity: Severity
    default_confidence: Confidence
    description: str
    detection: str
    evidence_requirements: list[str]
    remediation: str
    check: RuleCheck
    references: list[dict[str, str]] = field(default_factory=list)
    #: Observations kinds the rule must have present before it can run. If any
    #: requirement is missing the rule is skipped and reported as skipped, not
    #: as "passed".
    requires: list[str] = field(default_factory=list)
    #: Whether missing evidence means the rule is inapplicable (default) or is
    #: itself a violation. Missing HSTS is a violation only if we got an HTTPS
    #: response at all.
    applies_when: Callable[[RuleContext], bool] | None = None
    enabled: bool = True

    def can_run(self, context: RuleContext) -> bool:
        """Whether this rule has the observations it needs."""
        if not self.enabled:
            return False
        if not all(context.has_kind(kind) for kind in self.requires):
            return False
        if self.applies_when is not None and not self.applies_when(context):
            return False
        return True

    @property
    def qualified_id(self) -> str:
        return f"{self.category.value}:{self.rule_id}"


@dataclass
class RuleSkipped:
    """Recorded when a rule could not run, and why."""

    rule_id: str
    reason: str


@dataclass
class EvaluationResult:
    """Outcome of evaluating a ruleset against one asset."""

    matches: list[tuple[RuleDefinition, RuleMatch]] = field(default_factory=list)
    evaluated: int = 0
    skipped: list[RuleSkipped] = field(default_factory=list)
