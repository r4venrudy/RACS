from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, StringConstraints

Text = Annotated[str, StringConstraints(min_length=1, max_length=4096)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Finding(StrictModel):
    id: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._:-]{1,128}$")]
    type: Text
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    confidence_rationale: Text
    verification_status: Literal["observation", "indicator", "verified"]
    affected_url: HttpUrl
    affected_parameter: Text | None
    evidence: Text
    reproduction_steps: list[Text] = Field(min_length=1, max_length=20)
    remediation: Text
    sample_fix_snippet: Text


class ChallengeRequest(StrictModel):
    target: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    method: Literal["dns", "https"]


class ScanRequest(StrictModel):
    target: Annotated[str, StringConstraints(min_length=1, max_length=2048)]


class ScanSession(StrictModel):
    id: str
    owner: str
    origin: str
    status: Literal[
        "queued", "running", "cancelled", "interrupted", "not_performed", "failed", "completed"
    ]
    created_at: float
    updated_at: float
    detail: str
