
import re
import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)

class SemanticMapper:
    """
    Discovers network fields (IPs, Ports, Timestamps) by analyzing data content.
    Aligns arbitrary headers to ECS standards.
    """

    IP_REGEX = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

    ALIAS_MAP = {
        "@timestamp": ["ts", "time", "date", "datetime", "event_time", "frame.time_epoch", "start"],
        "source.ip": ["src", "src_ip", "client_ip", "orig_h", "source", "ip_src", "clienthost", "client"],
        "destination.ip": ["dst", "dst_ip", "server_ip", "resp_h", "destination", "ip_dst", "targetserver", "target"],
        "source.port": ["sport", "src_port", "client_port", "orig_p", "source_port"],
        "destination.port": ["dport", "dst_port", "server_port", "resp_p", "destination_port"],
        "network.transport": ["proto", "protocol", "transport", "prototype"],
        "network.bytes": ["bytes", "size", "length", "orig_bytes", "resp_bytes", "octets", "traffic"]
    }

    @classmethod
    def discover_and_map(cls, df: pd.DataFrame) -> pd.DataFrame:
        """
        Analyzes a DataFrame and renames columns to ECS standard based on content.
        """
        mapping = {}
        # Normalize column names for alias matching
        col_map = {col: col.lower().replace("_", "").replace(".", "").replace(" ", "") for col in df.columns}

        # 1. First Pass: Fuzzy Alias Matching
        for ecs_name, aliases in cls.ALIAS_MAP.items():
            for original_col, normalized_col in col_map.items():
                if any(alias in normalized_col for alias in aliases):
                    if ecs_name not in mapping.values() and original_col not in mapping:
                        mapping[original_col] = ecs_name
                        logger.info(f"SEMANTIC: Matched Alias '{original_col}' -> '{ecs_name}'")
                        break

        # 2. Second Pass: Content Discovery for unmapped critical fields
        remaining_cols = [c for c in df.columns if c not in mapping]

        # Discover IPs
        if "source.ip" not in mapping.values() or "destination.ip" not in mapping.values():
            for col in remaining_cols:
                sample = df[col].dropna().head(20).astype(str)
                if sample.empty: continue
                if all(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val) for val in sample):
                    if "source.ip" not in mapping.values():
                        mapping[col] = "source.ip"
                        logger.info(f"SEMANTIC: Discovered IP Content '{col}' -> 'source.ip'")
                    elif "destination.ip" not in mapping.values():
                        mapping[col] = "destination.ip"
                        logger.info(f"SEMANTIC: Discovered IP Content '{col}' -> 'destination.ip'")

        # Discover Ports
        remaining_cols = [c for c in df.columns if c not in mapping]
        if "source.port" not in mapping.values() or "destination.port" not in mapping.values():
            for col in remaining_cols:
                try:
                    sample = pd.to_numeric(df[col].dropna().head(20), errors='coerce')
                    if sample.empty or sample.isnull().any(): continue
                    if all(0 <= val <= 65535 for val in sample):
                        if "source.port" not in mapping.values():
                            mapping[col] = "source.port"
                            logger.info(f"SEMANTIC: Discovered Port Content '{col}' -> 'source.port'")
                        elif "destination.port" not in mapping.values():
                            mapping[col] = "destination.port"
                            logger.info(f"SEMANTIC: Discovered Port Content '{col}' -> 'destination.port'")
                except:
                    pass

        if mapping:
            logger.info(f"Final Semantic Mapping Selection: {mapping}")
            return df.rename(columns=mapping)
        
        return df
