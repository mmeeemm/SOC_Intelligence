
import logging
import subprocess
import pandas as pd
import os
import re
import tempfile
import shutil
from pathlib import Path
from threading import Thread
import time

logger = logging.getLogger(__name__)

# Paths (Configured for Snort 3 in Production)
SNORT_BIN = "/usr/local/bin/snort"
SNORT_CONF = "archive_legacy/snort_config/config/snort/snort.lua"
SNORT_RULE_PATH = "archive_legacy/snort_config/config/snort/rules"

class SnortService:
    """
    Manages Intrusion Detection System (IDS) execution.
    Non-blocking, offline PCAP analysis (no sudo required).
    """

    def __init__(self):
        self.last_alerts = pd.DataFrame()
        self._check_snort()

    def _check_snort(self):
        """Check for Snort 3 and Snort 2 availability"""
        self.snort_available = False
        self.snort2_available = False

        try:
            # Check Snort 3
            s3 = subprocess.run(['which', 'snort'], capture_output=True, text=True)
            if s3.returncode == 0:
                test = subprocess.run(['snort', '--version'], capture_output=True, text=True)
                if "Snort 3" in test.stdout or "Snort++" in test.stdout:
                    self.snort_available = True
                    logger.info("[DONE] Snort 3 detected (Primary IDS)")

            # Check Snort 2
            s2 = subprocess.run(['which', 'snort2'], capture_output=True, text=True)
            if s2.returncode == 0 or os.path.exists("/usr/local/bin/snort2"):
                self.snort2_available = True
                logger.info("[DONE] Snort 2 detected")

            if self.snort_available or self.snort2_available:
                logger.info("Snort Service: Operational (Full Overdrive Enabled)")
        except Exception as e:
            logger.warning(f"WARNING Snort check failed: {e}")

    def is_available(self) -> bool:
        """Check if Snort IDS is available"""
        return self.snort_available or self.snort2_available

    def run_on_pcap_async(self, pcap_path: str, callback=None, timeout=60):
        """Execute Snort analysis asynchronously (non-blocking)."""
        def _analyze():
            try:
                alerts = self.run_on_pcap(pcap_path, timeout=timeout)
                self.last_alerts = alerts
                if callback:
                    callback(alerts)
            except Exception as e:
                logger.error(f"Async Snort analysis failed: {e}")
                if callback:
                    callback(pd.DataFrame())

        thread = Thread(target=_analyze, daemon=True)
        thread.start()
        return thread

    def run_on_pcap(self, pcap_path: str, timeout=60) -> pd.DataFrame:
        """Execute Snort analysis on a PCAP file (Hybrid 2+3 Overdrive)."""
        if not self.is_available():
            logger.warning("No Snort engines available")
            return pd.DataFrame()

        all_alerts = []
        with tempfile.TemporaryDirectory() as temp_dir:
            # 1. Snort 3 (Primary)
            if self.snort_available:
                try:
                    cmd3 = [SNORT_BIN, "-c", SNORT_CONF, "-r", pcap_path, "-l", temp_dir, "-A", "fast", "-q", "-z", "20"]
                    subprocess.run(cmd3, check=False, timeout=timeout)
                    s3_file = os.path.join(temp_dir, "alert_fast.txt")
                    if os.path.exists(s3_file):
                        df3 = self._parse_alerts(s3_file)
                        if not df3.empty: all_alerts.append(df3)
                except Exception as e:
                    logger.error(f"Snort 3 failed: {e}")

            # 2. Snort 2 (Legacy Supplement)
            if self.snort2_available:
                try:
                    s2_dir = os.path.join(temp_dir, "snort2")
                    os.makedirs(s2_dir, exist_ok=True)
                    cmd2 = ["snort2" if shutil.which("snort2") else "/usr/local/bin/snort2",
                            "-c", "archive_legacy/snort_config/config/snort/snort2.conf" if os.path.exists("archive_legacy/snort_config/config/snort/snort2.conf") else SNORT_CONF,
                            "-r", pcap_path, "-l", s2_dir, "-A", "fast", "-q"]
                    subprocess.run(cmd2, check=False, timeout=timeout)
                    s2_file = os.path.join(s2_dir, "alert")
                    if os.path.exists(s2_file):
                        df2 = self._parse_alerts(s2_file)
                        if not df2.empty: all_alerts.append(df2)
                except Exception as e:
                    logger.error(f"Snort 2 failed: {e}")

        if not all_alerts:
            return pd.DataFrame()

        return pd.concat(all_alerts).drop_duplicates(subset=['@timestamp', 'alert.message', 'source.ip', 'destination.ip'])

    def _parse_alerts(self, alert_file_path: str) -> pd.DataFrame:
        """Parse 'alert_fast' format into ECS Hybrid Schema."""
        regex = r"(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\] \[(?P<sid>\d+:\d+:\d+)\] (?P<msg>.+?) \[\*\*\] (?:\[Classification: .+?\] )?\[Priority: (?P<priority>\d+)\] \{(?P<proto>\w+)\} (?P<source_ip>[\d\.]+)(?::(?P<source_port>\d+))? -> (?P<destination_ip>[\d\.]+)(?::(?P<destination_port>\d+))?"
        data = []
        import datetime
        current_year = datetime.datetime.now().year

        try:
            with open(alert_file_path, 'r') as f:
                for line in f:
                    match = re.search(regex, line)
                    if match:
                        item = match.groupdict()
                        try:
                            ts_str = item.get('timestamp')
                            dt = datetime.datetime.strptime(f"{current_year}-{ts_str}", "%Y-%m/%d-%H:%M:%S.%f")
                            final_ts = dt
                        except:
                            final_ts = datetime.datetime.now()

                        row = {
                            "@timestamp": final_ts,
                            "source.ip": item.get('source_ip'),
                            "source.port": int(item.get('source_port', 0)) if item.get('source_port') else 0,
                            "destination.ip": item.get('destination_ip'),
                            "destination.port": int(item.get('destination_port', 0)) if item.get('destination_port') else 0,
                            "network.transport": item.get('proto').lower(),
                            "alert.message": item.get('msg').strip() if item.get('msg') else "Unknown Alert",
                            "data.source": "snort",
                            "network.protocol": "ids_alert"
                        }

                        from src.utils.forensics import generate_community_id
                        row['network.community_id'] = generate_community_id(
                            row['source.ip'], row['destination.ip'],
                            row['source.port'], row['destination.port'],
                            row['network.transport']
                        )
                        row['risk_score'] = self._priority_to_risk(item.get('priority', '3'))
                        data.append(row)

            return pd.DataFrame(data)
        except Exception as e:
            logger.error(f"Alert Parsing Failed: {e}")
            return pd.DataFrame()

    def _priority_to_risk(self, priority: str) -> int:
        """Map Snort Priority (1-3) to Blink Risk Score (0-100)."""
        try:
            p = int(priority)
            if p == 1: return 90
            if p == 2: return 60
            return 30
        except:
            return 10
