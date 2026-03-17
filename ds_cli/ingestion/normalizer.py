import re
from typing import Dict, Any
from datetime import datetime
from dateutil import parser as date_parser
from ds_cli.ingestion.models import NormalizedLog

# Regex for extracting IPs
IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# Regex for common log timestamps (ISO8601 and Syslog-like)
TIMESTAMP_PATTERN = re.compile(
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)|'  # ISO8601
    r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'                         # Syslog (e.g. Oct 25 14:32:01)
)

# Regex for mapping common words to event types
EVENT_TYPE_MAP = {
    "auth": "AUTHENTICATION",
    "login": "AUTHENTICATION",
    "failed": "AUTH_FAILURE",
    "fail": "AUTH_FAILURE",
    "error": "ERROR",
    "brute": "BRUTE_FORCE",
    "sudo": "PRIVILEGE_ESCALATION"
}

def extract_ip(text: str) -> str:
    match = IP_PATTERN.search(text)
    return match.group(0) if match else None

def extract_timestamp(text: str) -> str:
    match = TIMESTAMP_PATTERN.search(text)
    return match.group(0) if match else None

def guess_event_type(text: str) -> str:
    text_lower = text.lower()
    for keyword, ev_type in EVENT_TYPE_MAP.items():
        if keyword in text_lower:
            return ev_type
    return "UNKNOWN"

def normalize_log(parsed_data: Dict[str, Any]) -> NormalizedLog:
    """Converts parsed text or JSON into the NormalizedLog schema."""
    message = parsed_data.get("message", "")
    raw_data = parsed_data.get("raw_data", "")
    metadata = parsed_data.get("metadata", {})

    # Log forging mitigation: Remove newline characters from message and raw_data
    message = message.replace('\n', ' ').replace('\r', '')
    raw_data = raw_data.replace('\n', ' ').replace('\r', '')

    # ReDoS mitigation: Truncate message/raw_data before running regex
    max_regex_len = 1000
    trunc_message = message[:max_regex_len]
    trunc_raw_data = raw_data[:max_regex_len]

    # Extract common fields
    source_ip = metadata.get("ip") or metadata.get("source_ip") or extract_ip(trunc_message) or extract_ip(trunc_raw_data)
    event_type = metadata.get("event_type") or guess_event_type(trunc_message)
    
    # Try parsing timestamp
    ts_str = metadata.get("timestamp") or metadata.get("time") or extract_timestamp(trunc_raw_data)
    ts = datetime.utcnow()
    if ts_str:
        try:
            # Use dateutil parser to handle various confusing string formats robustly
            parsed_ts = date_parser.parse(ts_str)
            # Make naive for correlation math
            ts = parsed_ts.replace(tzinfo=None)
        except Exception:
            pass # Keep default fallback

    # Determine a basic initial severity based on event_type 
    severity = "INFO"
    if event_type in ["AUTH_FAILURE", "ERROR"]:
        severity = "MEDIUM"
    elif event_type in ["BRUTE_FORCE"]:
        severity = "HIGH"
        
    # Let metadata override severity if present
    severity = metadata.get("severity", severity).upper()

    return NormalizedLog(
        timestamp=ts,
        source_ip=source_ip,
        event_type=event_type,
        severity=severity,
        message=message,
        raw_data=raw_data,
        metadata=metadata
    )
