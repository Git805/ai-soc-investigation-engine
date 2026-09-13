from pydantic import BaseModel


class AuthenticationEventData(BaseModel):
    action: str
    result: str
    source_ip: str | None = None
    authentication_method: str | None = None
