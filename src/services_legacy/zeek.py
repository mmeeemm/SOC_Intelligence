
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

class ZeekService:
    """
    Service for executing Zeek (Network Monitoring) on PCAP files.
    Generates high-fidelity metadata for protocol analysis.
    """

    def __init__(self, zeek_bin="/usr/local/zeek/bin/zeek"):
        self.zeek_bin = zeek_bin
        self.config_path = "archive_legacy/snort_config/config/zeek/comprehensive.zeek"

    def is_available(self) -> bool:
        return subprocess.run(["which", self.zeek_bin], capture_output=True).returncode == 0

    def run_on_pcap(self, pcap_path: str, output_dir: str) -> bool:
        """
        Runs Zeek on a PCAP and outputs JSON logs to the specified directory.
        """
        if not self.is_available():
            logger.error("Zeek binary not found.")
            return False

        path = Path(pcap_path)
        if not path.exists():
            logger.error(f"PCAP not found: {pcap_path}")
            return False

        os.makedirs(output_dir, exist_ok=True)

        # Zeek command: -C (ignore checksums), -r (read pcap)
        # We enforce JSON output for reliable parsing
        cmd = [
            self.zeek_bin,
            "-C", "-r", os.path.abspath(pcap_path),
            "LogAscii::use_json=T"
        ]

        # Add comprehensive policy if available
        if os.path.exists(self.config_path):
            cmd.append(os.path.abspath(self.config_path))
        else:
            cmd.append("local") # Fallback to standard local policy

        try:
            logger.info(f"Executing Zeek on {path.name}...")

            # CRITICAL: Configure ZEEKPATH to find custom scripts
            script_dir = Path(self.config_path).parent / "scripts"
            env = os.environ.copy()
            # Zeek's default path should be preserved
            env["ZEEKPATH"] = f".:{os.path.abspath(Path(self.config_path).parent)}:{script_dir}:/usr/local/zeek/share/zeek:/usr/local/zeek/share/zeek/policy:/usr/local/zeek/share/zeek/site"

            # Zeek writes logs to CWD, so we change it to output_dir
            result = subprocess.run(cmd, cwd=output_dir, capture_output=True, text=True, env=env)

            if result.returncode != 0:
                logger.error(f"Zeek execution failed: {result.stderr}")
                return False

            logger.info(f"Zeek processing complete. Logs generated in {output_dir}")
            return True
        except Exception as e:
            logger.error(f"Zeek service error: {e}", exc_info=True)
            return False
