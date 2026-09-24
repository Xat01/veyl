"""Safety package: the network safety floor and the authorization boundary."""

from veyl_api.safety.firewall import (
    TargetRejection,
    TargetRejectionReason,
    UnsafeTargetError,
    ValidatedTarget,
    ValidationResult,
    classify_address,
    normalize_hostname,
    validate_port,
    validate_target,
    validate_targets,
)
from veyl_api.safety.scope import ScopeDecision, ScopeGuard, ScopeMatch, domain_matches, ip_in_cidr

__all__ = [
    "ScopeDecision",
    "ScopeGuard",
    "ScopeMatch",
    "TargetRejection",
    "TargetRejectionReason",
    "UnsafeTargetError",
    "ValidatedTarget",
    "ValidationResult",
    "classify_address",
    "domain_matches",
    "ip_in_cidr",
    "normalize_hostname",
    "validate_port",
    "validate_target",
    "validate_targets",
]
