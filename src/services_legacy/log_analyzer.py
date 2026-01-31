
import os
import json
import logging
from src.services.llm import llm

logger = logging.getLogger(__name__)

class LogAnalyzerService:
    """
    Service to analyze internal system logs using SecGPT.
    """
    def __init__(self, log_path="logs/app_json.log"):
        self.log_path = log_path

    def get_recent_logs(self, n=50):
        """
        Reads the last N lines from the JSON log file.
        """
        if not os.path.exists(self.log_path):
            return []

        try:
            with open(self.log_path, "r") as f:
                lines = f.readlines()
                last_n = lines[-n:]
            return [json.loads(line) for line in last_n]
        except Exception as e:
            logger.error(f"Failed to read logs: {e}")
            return []

    def analyze_system_health(self):
        """
        Sends normalized recent logs to the LLM for health diagnosis.
        """
        logs = self.get_recent_logs(50)
        if not logs:
            return "No logs available for analysis."

        from src.utils.toon_normalizer import ToonNormalizer
        # Convert list of dicts back to lines for the normalizer
        raw_lines = [json.dumps(log) for log in logs]
        normalized_context = ToonNormalizer.process_stream(raw_lines)

        if normalized_context == "TOON_EMPTY":
            return "Logs were pruned to empty after TOON normalization. No significant events for analysis."

        return llm.diagnose_system(normalized_context)

# Global Instance
log_analyzer = LogAnalyzerService()
