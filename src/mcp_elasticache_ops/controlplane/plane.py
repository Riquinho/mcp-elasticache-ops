"""The ControlPlane facade: every control-plane view as one class."""

from __future__ import annotations

from .upgrade import _UpgradeMixin


class ControlPlane(_UpgradeMixin):
    """Read-only ElastiCache and CloudWatch views; see the mixins for the individual tools."""
