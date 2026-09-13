from pydantic import BaseModel, Field


class NetworkEventData(BaseModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_domain: str | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = None
