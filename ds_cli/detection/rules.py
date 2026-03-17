import hashlib
import uuid
from typing import List, Dict
from datetime import datetime, timedelta
from ds_cli.ingestion.models import NormalizedLog
from ds_cli.detection.models import Alert

# Thresholds
BRUTE_FORCE_THRESHOLD = 5 # failures
BRUTE_FORCE_WINDOW_SEC = 60

class DetectionEngine:
    def __init__(self):
        self.alerts: List[Alert] = []
        self._auth_failures: Dict[str, List[datetime]] = {} # IP -> list of fail timestamps

    def _generate_alert_id(self) -> str:
        return f"AL-{uuid.uuid4().hex[:8].upper()}"

    def _generate_dedup_key(self, ip: str, alert_type: str) -> str:
        s = f"{ip}_{alert_type}"
        return hashlib.md5(s.encode()).hexdigest()

    def process_logs(self, logs: List[NormalizedLog]) -> List[Alert]:
        """Process a batch of logs and return generated alerts."""
        new_alerts = []
        
        # We sort logs by time just to process them in order
        sorted_logs = sorted(logs, key=lambda x: x.timestamp)
        
        for log in sorted_logs:
            # 1. Individual Auth Failures
            if log.event_type == "AUTH_FAILURE" and log.source_ip:
                # Add to tracking
                if log.source_ip not in self._auth_failures:
                    self._auth_failures[log.source_ip] = []
                self._auth_failures[log.source_ip].append(log.timestamp)
                
                # Check for brute force
                recent_fails = [
                    t for t in self._auth_failures[log.source_ip] 
                    if (log.timestamp - t).total_seconds() <= BRUTE_FORCE_WINDOW_SEC
                ]
                self._auth_failures[log.source_ip] = recent_fails # cleanup old entries
                
                if len(recent_fails) >= BRUTE_FORCE_THRESHOLD:
                    # Brute Force Alert
                    dup_key = self._generate_dedup_key(log.source_ip, "BRUTE_FORCE")
                    if not self._is_duplicate(dup_key):
                        alert = Alert(
                            alert_id=self._generate_alert_id(),
                            timestamp=log.timestamp,
                            title="Potential Brute Force Attack",
                            description=f"Detected {len(recent_fails)} authentication failures from IP {log.source_ip} within {BRUTE_FORCE_WINDOW_SEC} seconds.",
                            severity="HIGH",
                            source_ip=log.source_ip,
                            related_logs=[log], # In a real system, we'd slice the last N logs
                            deduplication_key=dup_key
                        )
                        new_alerts.append(alert)
                        self.alerts.append(alert)
                else:
                    # Single Auth Failure Alert (if we want them individually)
                    # For a cleaner CLI, maybe we don't alert on single fails unless asked, 
                    # but the task requires detecting auth failures. Let's make it a low priority alert.
                    dup_key = self._generate_dedup_key(log.source_ip, "SINGLE_AUTH_FAIL")
                    if not self._is_duplicate(dup_key):
                        alert = Alert(
                            alert_id=self._generate_alert_id(),
                            timestamp=log.timestamp,
                            title="Authentication Failure",
                            description=f"Authentication failed from IP {log.source_ip}.",
                            severity="LOW",
                            source_ip=log.source_ip,
                            related_logs=[log],
                            deduplication_key=dup_key
                        )
                        new_alerts.append(alert)
                        self.alerts.append(alert)

            # 2. Suspicious IP Activity (e.g., lots of requests in general, or error rates)
            # This is a stub for more complex heuristics (e.g. port scanning logs if available)
            if log.event_type == "ERROR" and log.severity == "CRITICAL":
                dup_key = self._generate_dedup_key(log.source_ip or "unknown", "CRITICAL_ERROR")
                if not self._is_duplicate(dup_key):
                    alert = Alert(
                        alert_id=self._generate_alert_id(),
                        timestamp=log.timestamp,
                        title="Critical System Error Detected",
                        description=f"A critical error was logged.",
                        severity="CRITICAL",
                        source_ip=log.source_ip,
                        related_logs=[log],
                        deduplication_key=dup_key
                    )
                    new_alerts.append(alert)
                    self.alerts.append(alert)

        return new_alerts

    def _is_duplicate(self, dedup_key: str) -> bool:
        """Simple deduplication: check if we already fired this alert signature."""
        for a in self.alerts:
            if a.deduplication_key == dedup_key:
                return True
        return False
