import logging
import re
from typing import Dict, Optional, Tuple

logger = logging.getLogger("MitreMapper")

class MitreMapper:
    """
    Maps network alerts and behaviors to MITRE ATT&CK tactics and techniques.
    Focuses on Snort signatures and common protocol anomalies.
    """

    # Mapping dictionary: Snort Message Fragment -> (Tactic, Technique ID)
    _SIGNATURE_MAP = {
    # Initial Access / Discovery
    r"SCAN": ("Discovery", "T1046"),
    r"Portscan": ("Discovery", "T1046"),
    r"NMAP": ("Discovery", "T1046"),
    r"Fingerprint": ("Discovery", "T1595"),
    r"INDICATOR-SCAN": ("Discovery", "T1046"),

    # Command and Control (C2)
    r"C2": ("Command and Control", "T1071"),
    r"Beacon": ("Command and Control", "T1071"),
    r"Reverse Shell": ("Command and Control", "T1059"),
    r"Metasploit": ("Command and Control", "T1071"),
    r"Cobalt Strike": ("Command and Control", "T1071"),
    r"INDICATOR-COMPROMISE": ("Command and Control", "T1071"),

    # Exfiltration
    r"Exfiltration": ("Exfiltration", "T1041"),
    r"Sensitive Data": ("Exfiltration", "T1041"),
    r"Data Leak": ("Exfiltration", "T1041"),

    # Persistence / Lateral Movement
    r"Lateral Movement": ("Lateral Movement", "T1210"),
    r"SMB": ("Lateral Movement", "T1021.002"),
    r"RDP": ("Lateral Movement", "T1021.001"),
    r"Pass-the-hash": ("Lateral Movement", "T1550.002"),

    # Execution / Exploitation
    r"Exploit": ("Execution", "T1203"),
    r"CVE-": ("Execution", "T1211"),
    r"Overflow": ("Execution", "T1212"),
    r"Injection": ("Execution", "T1059"),
    r"Shellcode": ("Execution", "T1059"),

    # Credential Access
    r"Brute Force": ("Credential Access", "T1110"),
    r"Password Spraying": ("Credential Access", "T1110.003"),
    r"Credential": ("Credential Access", "T1552"),

    # Malware / CNC
    r"Malware": ("Command and Control", "T1071"),
    r"CNC": ("Command and Control", "T1071"),
    r"Trojan": ("Impact", "T1485"), # General impact/malware

    # Web Attacks
    r"SQL": ("Initial Access", "T1190"),
    r"Webapp": ("Initial Access", "T1190"),
    r"robots.txt": ("Discovery", "T1595"),
    r"SERVER-WEBAPP": ("Initial Access", "T1190"),
    r"PROTOCOL-DNS": ("Discovery", "T1046"),
    }

    @classmethod
    def get_mitre_mapping(cls, alert_message: Optional[str]) -> Tuple[str, str]:
        """
        Derives MITRE Tactic and Technique from an alert message string.
        Returns ('Unknown', 'None') if no match found.
        """
        if not alert_message:
            return "Unknown", "None"

            for pattern, (tactic, technique) in cls._SIGNATURE_MAP.items():
                if re.search(pattern, alert_message, re.IGNORECASE):
                    return tactic, technique

                    return "Unknown", "None"

                    @classmethod
                    def get_sql_mapping_expression(cls, alert_col: str) -> str:
                        """
                        Generates a SQL CASE expression to perform MITRE mapping within DuckDB.
                        """
                        cases = []
                        for pattern, (tactic, technique) in cls._SIGNATURE_MAP.items():
                            # Escape single quotes for SQL
                            p_esc = pattern.replace("'", "''")
                            cases.append(f"WHEN {alert_col} ILIKE '%{p_esc}%' THEN '{tactic} ({technique})'")

                            return f"""
                            CASE
                            {" ".join(cases)}
                            WHEN {alert_col} IS NOT NULL THEN 'General/Unknown'
                            ELSE NULL
                            END
                            """
