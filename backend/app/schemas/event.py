from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from app.schemas.network import NetworkEventData


class EventType(StrEnum):
    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    FILE_EVENT = "file_event"
    REGISTRY_EVENT = "registry_event"
    AUTHENTICATION = "authentication"
    LOGON = "logon"
    SCRIPT = "script"
    ALERT = "alert"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Host(BaseModel):
    model_config = ConfigDict(extra="allow")
    hostname: str
    ip: str | None = None


class User(BaseModel):
    model_config = ConfigDict(extra="allow")
    username: str
    domain: str | None = None


class Process(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    pid: int | None = Field(default=None, ge=0)
    command_line: str | None = None
    executable_path: str | None = None


class ParentProcess(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    pid: int | None = Field(default=None, ge=0)


class Source(BaseModel):
    vendor: str
    product: str
    version: str | None = None


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"
    event_id: str = Field(min_length=1)
    timestamp: datetime
    event_type: EventType
    severity: Severity
    host: Host
    user: User | None = None
    process: Process | None = None
    parent_process: ParentProcess | None = None
    network: NetworkEventData | None = None
    source: Source
    data: dict[str, Any] = Field(default_factory=dict)
