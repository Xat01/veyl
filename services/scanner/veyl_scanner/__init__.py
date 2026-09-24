"""Scanner service: authorized discovery and observation collection.

The scanner's only job is to produce :class:`Observation` payloads. It never
creates findings, never assigns severity, and never interprets. Interpretation
belongs to the rule engine, which is why every finding can name the exact
observation it came from.
"""

__all__ = ["contracts"]
