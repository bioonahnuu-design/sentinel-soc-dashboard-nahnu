from datetime import datetime
from ipaddress import ip_address

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LogCreate(BaseModel):
    timestamp: datetime
    source_ip: str = Field(max_length=45)
    username: str = Field(min_length=1, max_length=100)
    event_type: str = Field(default="login", min_length=1, max_length=50)
    status: str = Field(max_length=20)
    user_agent: str | None = Field(default=None, max_length=512)
    country: str | None = Field(default=None, max_length=80)

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        value = value.strip()
        try:
            ip_address(value)
        except ValueError as exc:
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address") from exc
        return value

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("username cannot be empty")
        return normalized

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        normalized = value.lower().strip()
        if normalized not in {"success", "failed"}:
            raise ValueError("status must be success or failed")
        return normalized

    @field_validator("event_type")
    @classmethod
    def normalize_event_type(cls, value: str) -> str:
        normalized = value.lower().strip()
        if not normalized:
            raise ValueError("event_type cannot be empty")
        return normalized


class LogOut(LogCreate):
    id: int
    model_config = ConfigDict(from_attributes=True)


class AlertOut(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    rule_name: str
    source_ip: str
    acknowledged: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AlertDetail(AlertOut):
    incident_id: str
    log: LogOut | None = None


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int
