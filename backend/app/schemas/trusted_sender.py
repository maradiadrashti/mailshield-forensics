from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict


class TrustedSenderCreate(BaseModel):
    type: Literal["email", "domain"] = Field(..., description="Rule category: either exact email address or complete domain name")
    value: str = Field(..., min_length=1, max_length=255, description="The email address or domain name to trust")


class TrustedSenderResponse(BaseModel):
    id: str
    user_id: str
    type: str
    value: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
