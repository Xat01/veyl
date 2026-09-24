"""Rule registry and evaluation engine.

The registry is the single source of truth for which rules exist. The evaluator
walks a ruleset against one asset's observations, enforces the evidence contract,
and reports what it skipped and why.

Two invariants the evaluator enforces:

1. **No evidence, no finding.** A rule that returns a match citing no evidence
   is rejected outright. This is the mechanism that keeps the "evidence-first"
   claim honest rather than aspirational.
2. **No silent skips.** A rule that could not run is reported as skipped with a
   reason. "Zero findings" and "we did not look" must never be indistinguishable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from veyl_api.enums import RuleCategory
from veyl_rules.api_rules import API_RULES
from veyl_rules.auth_infra_rules import AUTHENTICATION_RULES, INFRASTRUCTURE_RULES
from veyl_rules.exposure_rules import EXPOSURE_RULES
from veyl_rules.framework import (
    EvaluationResult,
    RuleContext,
    RuleDefinition,
    RuleMatch,
    RuleSkipped,
)
from veyl_rules.network_rules import NETWORK_RULES
from veyl_rules.tls_rules import TLS_RULES
from veyl_rules.web_rules import WEB_RULES


def all_rules() -> list[RuleDefinition]:
    """Every rule Veyl ships, in a stable order."""
    return [
        *NETWORK_RULES,
        *TLS_RULES,
        *WEB_RULES,
        *API_RULES,
        *AUTHENTICATION_RULES,
        *INFRASTRUCTURE_RULES,
        *EXPOSURE_RULES,
    ]


def rules_by_category() -> dict[RuleCategory, list[RuleDefinition]]:
    grouped: dict[RuleCategory, list[RuleDefinition]] = {}
    for rule in all_rules():
        grouped.setdefault(rule.category, []).append(rule)
    return grouped


def get_rule(rule_id: str) -> RuleDefinition | None:
    return next((r for r in all_rules() if r.rule_id == rule_id), None)


@dataclass
class RuleRejection:
    """A match that was discarded because it violated the evidence contract."""

    rule_id: str
    reason: str
    match_summary: str


@dataclass
class EvaluationReport:
    """Full outcome of an evaluation run."""

    result: EvaluationResult = field(default_factory=EvaluationResult)
    rejections: list[RuleRejection] = field(default_factory=list)
    timings_ms: dict[str, float] = field(default_factory=dict)

    @property
    def matches(self) -> list[tuple[RuleDefinition, RuleMatch]]:
        return self.result.matches


def _validate_match(rule: RuleDefinition, match: RuleMatch, context: RuleContext) -> str | None:
    """Return a rejection reason, or None when the match is well-formed.

    This is the enforcement point for the evidence contract. It is deliberately
    strict: a partially-formed match is dropped rather than repaired.
    """
    if not match.evidence:
        return "match cites no evidence"

    for entry in match.evidence:
        if not isinstance(entry, dict):
            return "evidence entry is not an object"
        kind = entry.get("kind")
        if not kind:
            return "evidence entry has no observation kind"
        if not entry.get("matcher"):
            return f"evidence entry for kind {kind!r} states no matcher"
        # The cited observation kind must actually be present in the context.
        # This stops a rule citing a kind it never read.
        if not context.has_kind(str(kind)) and "business_context" not in str(kind):
            return f"evidence cites observation kind {kind!r} which is not present in context"

    if not match.detection_explanation.strip():
        return "match has no detection explanation"
    if not match.impact.strip():
        return "match has no impact statement"
    if not match.summary.strip():
        return "match has no summary"
    return None


def evaluate(
    context: RuleContext,
    *,
    rules: list[RuleDefinition] | None = None,
    categories: list[RuleCategory] | None = None,
) -> EvaluationReport:
    """Evaluate a ruleset against one asset context."""
    report = EvaluationReport()
    candidates = rules if rules is not None else all_rules()

    if categories:
        wanted = set(categories)
        candidates = [r for r in candidates if r.category in wanted]

    for rule in candidates:
        if not rule.enabled:
            report.result.skipped.append(
                RuleSkipped(rule_id=rule.rule_id, reason="rule is disabled")
            )
            continue

        if not rule.can_run(context):
            missing = [kind for kind in rule.requires if not context.has_kind(kind)]
            reason = (
                f"missing required observation(s): {', '.join(missing)}"
                if missing
                else "rule applicability condition not met for this asset"
            )
            report.result.skipped.append(RuleSkipped(rule_id=rule.rule_id, reason=reason))
            continue

        started = time.perf_counter()
        try:
            matches = rule.check(context)
        except Exception as exc:  # noqa: BLE001 - a broken rule must not kill a scan
            report.result.skipped.append(
                RuleSkipped(
                    rule_id=rule.rule_id,
                    reason=f"rule raised {type(exc).__name__}: {exc}",
                )
            )
            continue
        report.timings_ms[rule.rule_id] = round((time.perf_counter() - started) * 1000, 3)

        report.result.evaluated += 1
        for match in matches:
            rejection = _validate_match(rule, match, context)
            if rejection is not None:
                report.rejections.append(
                    RuleRejection(
                        rule_id=rule.rule_id,
                        reason=rejection,
                        match_summary=match.summary or "<no summary>",
                    )
                )
                continue
            report.result.matches.append((rule, match))

    return report


def rule_metadata() -> list[dict[str, Any]]:
    """Serialisable metadata for the rule catalogue API."""
    return [
        {
            "rule_id": rule.rule_id,
            "title": rule.title,
            "category": rule.category.value,
            "severity": rule.severity.value,
            "default_confidence": rule.default_confidence.value,
            "description": rule.description,
            "detection": rule.detection,
            "evidence_requirements": rule.evidence_requirements,
            "remediation": rule.remediation,
            "references": rule.references,
            "requires": rule.requires,
            "enabled": rule.enabled,
        }
        for rule in all_rules()
    ]
