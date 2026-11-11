from pydantic import BaseModel, Field


class Event(BaseModel):
    user_id: str
    user_name: str
    resource_id: str
    authenticated: bool
    asset_criticality: int = Field(ge=1, le=5)
    threat_probability: float = Field(ge=0, le=1)
    impact: float = Field(ge=1, le=10)
    requests_per_minute: float = Field(ge=0)
    failed_logins: int = Field(ge=0)
    label: str = "benign"
