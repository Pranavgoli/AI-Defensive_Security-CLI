import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def parse_plain_text_log(line: str) -> Dict[str, Any]:
    """Basic parser for plain text logs."""
    return {
        "message": line.strip(),
        "raw_data": line.strip(),
    }

def parse_json_log(line: str) -> Dict[str, Any]:
    """Parser for JSON formatted logs with error handling."""
    line = line.strip()
    try:
        data = json.loads(line)
        return {
            "message": data.get("message", line),
            "raw_data": line,
            "metadata": data
        }
    except json.JSONDecodeError:
        # Safe handling of malformed logs
        logger.warning(f"Malformed JSON log encountered, treating as plain text: {line}")
        return parse_plain_text_log(line)

def parse_log_file(file_path: str) -> List[Dict[str, Any]]:
    """Reads a file and yields parsed log dictionaries."""
    parsed_logs = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if not line.strip():
                    continue
                # Simple heuristic: if it starts with '{', try JSON parsing
                if line.strip().startswith('{'):
                    parsed_logs.append(parse_json_log(line))
                else:
                    parsed_logs.append(parse_plain_text_log(line))
    except Exception as e:
        logger.error(f"Failed to read log file {file_path}: {e}")
    return parsed_logs
