"""Rule catalogue endpoint.

Veyl's findings are only trustworthy if the rules behind them are inspectable.
This endpoint publishes the shipped rule set — what each rule looks for, what
observations it requires, how it is remediated — so a user can audit the logic
that produced a finding rather than take it on faith.

It reads the in-process registry, not the database. A rule is code; the database
holds which rules ran against which scan, not the rule definitions themselves.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from veyl_api.api.deps import require
from veyl_api.api.schemas import RuleOut

router = APIRouter()


def _rule_out(rule) -> RuleOut:
    return RuleOut(
        rule_id=rule.rule_id,
        title=rule.title,
        category=rule.category.value,
        severity=rule.severity,
        description=rule.description,
        requires_observations=list(rule.requires or []),
        remediation=rule.remediation,
        references=list(rule.references or []),
    )


@router.get("", response_model=list[RuleOut], summary="List the shipped detection rules")
def list_rules(context=require("rule:read")) -> list[RuleOut]:
    """Return every enabled rule Veyl can evaluate.

    Sorted by rule id so the order is stable across requests; a UI that groups by
    category can do so without the API imposing an order.
    """
    from veyl_rules import all_rules

    return [_rule_out(rule) for rule in sorted(all_rules(), key=lambda r: r.rule_id)]


@router.get("/{rule_id}", response_model=RuleOut, summary="Fetch one rule definition")
def get_rule_definition(rule_id: str, context=require("rule:read")) -> RuleOut:
    """Return a single rule with the observations it depends on."""
    from veyl_rules import get_rule

    rule = get_rule(rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no rule with id {rule_id!r} is shipped by this build",
        )
    return _rule_out(rule)


@router.get(
    "/meta/categories",
    response_model=dict[str, list[str]],
    summary="List rule categories and the rules in each",
)
def categories(context=require("rule:read")) -> dict[str, list[str]]:
    """Group rule ids by category, for navigation."""
    from veyl_rules import rules_by_category

    grouped = rules_by_category()
    return {
        (key.value if hasattr(key, "value") else str(key)): sorted(
            r.rule_id for r in rules
        )
        for key, rules in grouped.items()
    }
