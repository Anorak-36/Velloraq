# SPDX-License-Identifier: MIT
"""velloraq.integrations.base module for the Velloraq security platform."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from velloraq.scanner.models import Resource, ScanContext, ScanWarning


@dataclass
class CollectionResult:
    """CollectionResult component used by Velloraq. """
    resources: list[Resource] = field(default_factory=list)
    warnings: list[ScanWarning] = field(default_factory=list)


class ProviderIntegration(ABC):
    """ProviderIntegration component used by Velloraq. """
    provider: str

    @abstractmethod
    def collect(self, context: ScanContext) -> CollectionResult:
        """Collect normalized resources with official SDKs in read-only mode."""
