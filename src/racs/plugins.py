"""Plugins are trusted installed code. No remote discovery or upload is supported."""

from dataclasses import dataclass
from typing import Protocol

from racs.models import CheckOutcome
from racs.network import Response


@dataclass(frozen=True)
class Metadata:
    name: str
    category: str
    description: str


class RequestContext(Protocol):
    async def get_root(self) -> Response: ...
    async def get(self, path: str, params=None, principal=None) -> Response: ...
    def check_cancelled(self) -> None: ...


class Check(Protocol):
    metadata: Metadata

    async def run(self, context: RequestContext) -> CheckOutcome: ...
