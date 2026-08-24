from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal, Protocol

from pydantic import BaseModel, Field


class ReadIntent(BaseModel):
    """A model-selected request whose final scope is validated by normal code."""

    tool: Literal["get_resource", "list_resources", "pod_logs"]
    api_version: str | None = Field(default=None, max_length=128)
    kind: str | None = Field(default=None, max_length=128)
    namespace: str | None = Field(default=None, max_length=253)
    name: str | None = Field(default=None, max_length=253)
    label_selector: str | None = Field(default=None, max_length=512)
    container: str | None = Field(default=None, max_length=253)
    previous: bool = False
    limit: int = Field(default=20, ge=1, le=50)


class ReadPlan(BaseModel):
    scope_summary: str = Field(min_length=1, max_length=500)
    intents: list[ReadIntent] = Field(default_factory=list, max_length=6)
    limitations: list[str] = Field(default_factory=list, max_length=5)


@dataclass(frozen=True)
class AdHocObservation:
    id: str
    tool: str
    summary: str
    source: str
    collected_at: datetime
    data: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ReadResult:
    observations: tuple[AdHocObservation, ...]
    limitations: tuple[str, ...] = ()


class ReadOnlyExplorer(Protocol):
    def execute(self, intent: ReadIntent) -> ReadResult: ...
