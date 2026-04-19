from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "medium", "low"]
Decision = Literal["malicious", "suspicious", "under_review", "benign"]


class ThreatRecord(BaseModel):
    id: str
    file_name: str
    risk_score: int = Field(ge=0, le=100)
    source_ip: str
    behavior: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    reasoning: list[str]
    decision: Decision
    sha256: str
    file_size_bytes: int = Field(ge=0)
    created_at: datetime


class ThreatListResponse(BaseModel):
    threats: list[ThreatRecord]


class AnalyzeResponse(BaseModel):
    threat: ThreatRecord
    alerts: list[str]
    agent_logs: list[str]
    network_events: list[str]
    file_events: list[str]


class AlertListResponse(BaseModel):
    alerts: list[str]


class AgentLogListResponse(BaseModel):
    logs: list[str]


class SandboxEventsResponse(BaseModel):
    network_events: list[str]
    file_events: list[str]


class BlockIpRequest(BaseModel):
    ip: str
    reason: str | None = None


class BlockIpResponse(BaseModel):
    blocked: bool
    message: str
    blocked_ips: list[str]


class ReportResponse(BaseModel):
    report: dict[str, object]


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    llm: Literal["online", "degraded"]
    agents: Literal["running", "degraded"]
    sandbox: Literal["active", "degraded"]
    threat_count: int = Field(ge=0)
    blocked_ip_count: int = Field(ge=0)

