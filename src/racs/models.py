from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    StringConstraints,
    field_validator,
    model_validator,
)

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


class Probe(StrictModel):
    path: str
    parameter: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_]{1,64}$")]
    sql_context: Literal["string", "like", "numeric"] = "string"
    baseline: Annotated[str, StringConstraints(min_length=1, max_length=128)] = "1"

    @field_validator("path")
    @classmethod
    def safe_path(cls, value):
        from racs.scope import validate_path

        return validate_path(value)


class AccessCase(StrictModel):
    path: str
    owner_principal: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_-]{1,32}$")]
    other_principal: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_-]{1,32}$")]
    json_field: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_]{1,64}$")]
    expected_value: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    identity_path: str
    owner_identity: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    other_identity: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    marker_field: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_]{1,64}$")]
    private_marker: Annotated[str, StringConstraints(min_length=12, max_length=128)]

    @field_validator("path", "identity_path")
    @classmethod
    def safe_path(cls, value):
        from racs.scope import validate_path

        return validate_path(value)

    @model_validator(mode="after")
    def independent_controls(self):
        if self.marker_field == self.json_field or self.private_marker == self.expected_value:
            raise ValueError("Private marker must be independent of the object identifier")
        if self.private_marker in self.path or self.private_marker in self.identity_path:
            raise ValueError("Private marker must never be sent in a request")
        if (
            self.owner_identity == self.other_identity
            or self.owner_principal == self.other_principal
        ):
            raise ValueError("Distinct test identities are required")
        return self


class ScanPlan(StrictModel):
    checks: list[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,31}$")]] = Field(
        default_factory=lambda: ["headers"], min_length=1, max_length=4
    )
    header_path: str = "/"
    probes: list[Probe] = Field(default_factory=list, max_length=3)
    access_cases: list[AccessCase] = Field(default_factory=list, max_length=3)
    read_only_confirmed: bool = False

    @field_validator("header_path")
    @classmethod
    def safe_path(cls, value):
        from racs.scope import validate_path

        return validate_path(value)


class ScanRequest(StrictModel):
    target: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    plan: ScanPlan = Field(default_factory=ScanPlan)
    credentials: dict[str, str] = Field(default_factory=dict, max_length=6)

    @field_validator("credentials")
    @classmethod
    def safe_credentials(cls, values):
        import re

        for alias, token in values.items():
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", alias) or not re.fullmatch(
                r"[A-Za-z0-9._~+/=-]{1,2048}", token
            ):
                raise ValueError("Use short principal aliases and bearer tokens without whitespace")
        return values


class CheckOutcome(StrictModel):
    check: str
    status: Literal["findings", "no_finding", "not_performed", "inconclusive"]
    detail: Text
    findings: list[Finding] = Field(default_factory=list, max_length=30)


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
