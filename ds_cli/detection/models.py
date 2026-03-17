from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from ds_cli.ingestion.models import NormalizedLog

class Alert(BaseModel):
    """Schema for detected alerts."""
    alert_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    title: str
    description: str
    severity: str = "INFO" # Rule-based severity (can be upgraded by AI later)
    source_ip: Optional[str] = None
    related_logs: List[NormalizedLog] = Field(default_factory=list)
    deduplication_key: str
