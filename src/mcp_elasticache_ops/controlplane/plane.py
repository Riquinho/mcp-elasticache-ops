"""The ControlPlane facade: every control-plane view as one class."""

from __future__ import annotations

from .scale_view import _ScaleMixin


class ControlPlane(_ScaleMixin):
    """Read-only ElastiCache and CloudWatch views; see the mixins for the individual tools."""
