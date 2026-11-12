"""The ControlPlane facade: every control-plane view as one class."""

from __future__ import annotations

from .triage import _TriageMixin


class ControlPlane(_TriageMixin):
    """Read-only ElastiCache and CloudWatch views; see the mixins for the individual tools."""
