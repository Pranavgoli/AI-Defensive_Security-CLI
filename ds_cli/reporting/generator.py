import os
import logging
from datetime import datetime
from ds_cli.config import settings

logger = logging.getLogger(__name__)

def save_report(alert_id: str, report_content: str) -> str:
    """Saves the markdown incident report to the configured output directory."""
    os.makedirs(settings.output_dir, exist_ok=True)
    
    # Path Traversal Defense: sanitize the alert_id
    safe_alert_id = os.path.basename(alert_id).replace("..", "").replace("/", "").replace("\\", "")
    
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"INCIDENT_{safe_alert_id}_{timestamp_str}.md"
    filepath = os.path.join(settings.output_dir, filename)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        return filepath
    except Exception as e:
        logger.error(f"Failed to save report to {filepath}: {e}")
        return ""
