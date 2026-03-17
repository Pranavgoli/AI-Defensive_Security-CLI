import json
import logging
from typing import Dict, Any
from openai import OpenAI
from ds_cli.config import settings
from ds_cli.detection.models import Alert
from ds_cli.ai.prompts import prompt_classification_rca, prompt_incident_report

logger = logging.getLogger(__name__)

class AIAnalyzer:
    def __init__(self):
        # We use standard OpenAI client but point it to the local endpoint (e.g. Ollama)
        self.client = OpenAI(
            base_url=settings.ai_api_base,
            api_key=settings.ai_api_key
        )
        self.model = settings.ai_model

    def _call_llm(self, prompt: str) -> str:
        try:
            # Added a timeout to prevent the CLI from hanging during analysis
            # if the local Ollama/endpoint is offline.
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert security analyst."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # low temperature for stable output
                timeout=15.0 # Gracefully fail if taking too long
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            err_msg = f"Failed to call AI model {self.model}: {e}"
            logger.error(err_msg)
            # Return a fallback JSON string so parsing down the line doesn't crash completely,
            # or it will gracefully fall into the JSONDecodeError block.
            return f'{{"severity_classification": "UNKNOWN", "root_cause_analysis": "{err_msg}"}}'

    def analyze_alert(self, alert: Alert) -> Dict[str, Any]:
        """Performs AI classification and automatic Root Cause Analysis."""
        sanitized_logs = []
        for l in alert.related_logs:
            safe_msg = l.message.replace("```", "").replace("===", "")
            sanitized_logs.append(f"[{l.timestamp.isoformat()}] {l.event_type} - {safe_msg}")
        
        logs_context = "\n".join(sanitized_logs)
        
        prompt = prompt_classification_rca.format(
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            source_ip=alert.source_ip,
            logs_context=logs_context
        )
        
        response_text = self._call_llm(prompt)
        
        try:
            # Cleanup common markdown codeblock artifacts that models sometimes insert
            cleaned = response_text.replace("```json", "").replace("```", "").strip()
            result = json.loads(cleaned)
            # Upgrade or downgrade severity based on AI
            alert.severity = result.get("severity_classification", alert.severity).upper()
            if alert.severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                alert.severity = "INFO"
            
            return {
                "alert": alert,
                "root_cause": result.get("root_cause_analysis", "AI analysis failed to provide a root cause.")
            }
        except json.JSONDecodeError:
            logger.error("Failed to parse JSON response from AI.")
            return {
                "alert": alert,
                "root_cause": "Failed to parse AI response. Raw output: " + response_text
            }

    def generate_incident_report(self, analyzed_alert: Dict[str, Any]) -> str:
        """Generates a professional markdown report post-analysis."""
        alert = analyzed_alert["alert"]
        root_cause = analyzed_alert["root_cause"]
        
        logs_summary = "\n".join(
            [f"- {l.timestamp.isoformat()}: {l.message}" for l in alert.related_logs]
        )
        
        prompt = prompt_incident_report.format(
            title=alert.title,
            timestamp=alert.timestamp.isoformat(),
            severity=alert.severity,
            source_ip=alert.source_ip,
            root_cause=root_cause,
            logs_summary=logs_summary
        )
        
        report_markdown = self._call_llm(prompt)
        return report_markdown
