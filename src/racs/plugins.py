"""Plugins are trusted installed code. No remote discovery or upload is supported."""

from dataclasses import dataclass
from typing import Protocol

from racs.models import Finding
from racs.network import Response


@dataclass(frozen=True)
class Metadata:
    name: str
    category: str
    description: str


class RequestContext(Protocol):
    async def get_root(self) -> Response: ...
    def check_cancelled(self) -> None: ...


class Check(Protocol):
    metadata: Metadata

    async def run(self, context: RequestContext) -> list[Finding]: ...


# Step 1 has no scanning modules. Future modules register explicitly here.
CHECKS: tuple[Check, ...] = ()
