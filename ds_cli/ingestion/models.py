from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

class NormalizedLog(BaseModel):
    """Standard unified schema for all ingested logs."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: Optional[str] = None
    event_type: str = "UNKNOWN"
    severity: str = "INFO" 
    message: str
    raw_data: str # The original log line
    metadata: Dict[str, Any] = Field(default_factory=dict)
