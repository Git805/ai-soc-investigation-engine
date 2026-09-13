from pydantic import BaseModel, Field


class ProcessEventData(BaseModel):
    name: str = Field(min_length=1)
    pid: int | None = Field(default=None, ge=0)
    command_line: str | None = None
    executable_path: str | None = None
    parent_name: str | None = None
    parent_pid: int | None = Field(default=None, ge=0)
