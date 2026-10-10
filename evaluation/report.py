"""Measured-result schema. Unavailable timing is null, never invented zero."""
from __future__ import annotations
from typing import Literal

from pydantic import Field
from agent.dto import StrictModel, Hash


class CaseOutput(StrictModel):
    caseId: str
    environment: Literal["BASELINE", "FUSE"]
    repeat: int = Field(ge=1)
    status: Literal["COMPLETED", "ERROR"]
    state: str
    decision: Literal["ALLOW", "WAIT_APPROVAL", "DENY", "ERROR"]
    reasonCodes: list[str]
    attackInduced: bool
    policyBlocked: bool
    forbiddenPaymentCount: int = Field(ge=0)
    forbiddenPaidAmountKrw: int = Field(ge=0)
    actualDownstreamDepth: int = Field(ge=0, le=2)
    normalExpectedReached: bool | None
    unrelatedNormalExpected: int = Field(ge=0)
    unrelatedNormalCompleted: int = Field(ge=0)
    securityCheckDurationMs: float | None = Field(default=None, ge=0)
    quarantineLatencyMs: float | None = Field(default=None, ge=0)
    trace: dict
    exclusionReason: str | None
    fixtureHash: Hash
    pairedInputVersion: str | None = None
    pairedInputHash: Hash | None = None
    inputSnapshotHash: Hash | None = None
    responseByteHash: Hash | None = None
    modelOutputHash: Hash
    model: str
    promptVersion: str
    policyVersion: str
    mockReviewerVersion: str


class EvaluationReport(StrictModel):
    reportVersion: Literal["FUSE-EVALUATION-2"] = "FUSE-EVALUATION-2"
    inputReportVersion: str = "FUSE-EVALUATION-2"
    experimentId: str
    fixtureSetId: str
    fixtureHash: Hash
    status: Literal["COMPLETED", "FAILED", "INTERRUPTED"]
    modelMode: Literal["REPLAY", "LIVE"]
    resultsSource: Literal["JAVA_POSTGRES_EXECUTION"]
    syntheticModelOutputs: bool
    liveRobustnessMeasured: bool
    plannedCaseIds: list[str]
    repeatCount: int = Field(ge=1, le=10)
    caseOutputs: list[CaseOutput]
    metrics: dict
    limitations: list[str]
