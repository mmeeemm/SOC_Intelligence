
import pandas as pd
import numpy as np
import logging
from src.data.db_client import db

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Identifies forensic rarities (anomalies) in purified sightings.
    """

    @classmethod
    def detect_anomalies(cls, table_name="events") -> pd.DataFrame:
        """
        Runs statistical anomaly detection on purified sightings.
        """
        logger.info(f"SEARCH Detecting anomalies in {table_name}...")
        try:
            # Optimize: Only select columns needed
            cols = ["@timestamp", "source.ip", "destination.ip", "network.bytes", "risk_score"]
            cols_str = ", ".join([f'"{c}"' for c in cols])

            df = db.query(f"SELECT {cols_str} FROM {table_name} LIMIT 50000")
            if df.empty:
                return pd.DataFrame()

            # 1. Volume Anomaly (Z-Score on network.bytes)
            if 'network.bytes' in df.columns:
                mean_bytes = df['network.bytes'].mean()
                std_bytes = df['network.bytes'].std()
                if std_bytes > 0:
                    df['z_score_bytes'] = (df['network.bytes'] - mean_bytes) / std_bytes
                else:
                    df['z_score_bytes'] = 0

            # 2. Risk Anomaly (Z-Score on risk_score)
            if 'risk_score' in df.columns:
                mean_risk = df['risk_score'].mean()
                std_risk = df['risk_score'].std()
                if std_risk > 0:
                    df['z_score_risk'] = (df['risk_score'] - mean_risk) / std_risk
                else:
                    df['z_score_risk'] = 0

            # Define anomalies: |Z| > 3
            z_bytes_abs = df['z_score_bytes'].abs() if 'z_score_bytes' in df.columns else pd.Series(0, index=df.index)
            z_risk_abs = df['z_score_risk'].abs() if 'z_score_risk' in df.columns else pd.Series(0, index=df.index)
            risk_series = df['risk_score'].fillna(0) if 'risk_score' in df.columns else pd.Series(0, index=df.index)

            mask = (z_bytes_abs > 3) | (z_risk_abs > 3) | (risk_series >= 90)
            anomalies = df[mask].copy()

            def _describe(row):
                desc = []
                z_bytes = row.get('z_score_bytes', 0)
                z_risk = row.get('z_score_risk', 0)
                r_score = row.get('risk_score', 0)

                if pd.notna(z_bytes) and z_bytes > 3: desc.append("Volume Outlier (Large)")
                if pd.notna(z_bytes) and z_bytes < -3: desc.append("Volume Outlier (Tiny)")
                if pd.notna(z_risk) and z_risk > 3: desc.append("Statistical Risk Outlier")
                if pd.notna(r_score) and r_score >= 90: desc.append("Critical Risk Signature")

                return ", ".join(desc) if desc else "Minor Deviation"

            if not anomalies.empty:
                anomalies['anomaly_type'] = anomalies.apply(_describe, axis=1)
                anomalies = anomalies.sort_values(by='risk_score', ascending=False)
                logger.info(f"Found {len(anomalies)} anomalies.")
                return anomalies
            
            return pd.DataFrame()

        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return pd.DataFrame()
