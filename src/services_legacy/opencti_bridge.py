
import logging
import os
import json
from datetime import datetime
from typing import Dict, List, Optional
from src.data.db_client import db

try:
    from pycti import OpenCTIApiClient
    from stix2 import (
        Incident, IPv4Address, DomainName, NetworkTraffic,
        Relationship, Bundle, Identity, ExternalReference
    )
    HAS_OPENCTI_LIBS = True
except ImportError:
    HAS_OPENCTI_LIBS = False

logger = logging.getLogger("OpenCTIBridge")

class OpenCTIBridge:
    """
    Forensic Intelligence Bridge: Synchronizes purified sightings from One_Blink
    to the OpenCTI Platform as STIX 2.1 bundles.
    """

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None):
        self.url = url or os.getenv("OPENCTI_URL", "http://localhost:8080")
        self.token = token or os.getenv("OPENCTI_TOKEN")
        self.client = None
        self.active = False

        if not HAS_OPENCTI_LIBS:
            logger.warning("OpenCTI libraries (pycti, stix2) missing. Sync disabled.")
            return

        if not self.token:
            logger.warning("OPENCTI_TOKEN not provided. Sync disabled.")
            return

        try:
            self.client = OpenCTIApiClient(self.url, self.token)
            self.active = True
            logger.info(f"OpenCTI Bridge active at {self.url}")
        except Exception as e:
            logger.error(f"Failed to connect to OpenCTI: {e}")
            self.active = False

    def sync_purified_sightings(self, limit: int = 100):
        """
        Reads from 'purified_events' and pushes to OpenCTI.
        """
        if not self.active:
            return False

        logger.info(f"Syncing top {limit} purified sightings to OpenCTI...")

        # Fetch Top High Risk Purified Sightings
        query = f"""
        SELECT * FROM purified_events
        WHERE risk_score > 0
        ORDER BY risk_score DESC
        LIMIT {limit}
        """
        df = db.query(query)

        if df.empty:
            logger.info("No purified records to sync.")
            return True

        try:
            # 1. Identity for One_Blink
            author = Identity(name="One_Blink Forensic Platform", identity_class="system")
            objects = [author]

            # 2. Main Incident Context
            incident = Incident(
                name=f"Forensic Consolidation: {datetime.now().strftime('%Y-%m-%d')}",
                description="Automated sync of discovery identify.",
                created_by_ref=author.id
            )
            objects.append(incident)

            # 3. Process Rows into STIX Observables
            for _, row in df.iterrows():
                try:
                    src_ip = IPv4Address(value=row['source.ip'])
                    dst_ip = IPv4Address(value=row['destination.ip'])

                    traffic = NetworkTraffic(
                        start=row['@timestamp'],
                        src_ref=src_ip.id,
                        dst_ref=dst_ip.id,
                        protocols=[row['network.protocol']],
                        byte_count=int(row['network.bytes'])
                    )

                    rel = Relationship(
                        source_ref=incident.id,
                        target_ref=traffic.id,
                        relationship_type="related-to",
                        description=f"Risk Score: {row['risk_score']} | Tools: {row['fused_sources']}"
                    )
                    objects.extend([src_ip, dst_ip, traffic, rel])
                except:
                    continue

            # 4. Push Bundle
            bundle = Bundle(objects=objects)
            self.client.stix2.import_bundle(bundle.serialize())

            logger.info(f"[DONE] Successfully pushed {len(df)} sightings to OpenCTI.")
            return True

        except Exception as e:
            logger.error(f"OpenCTI Sync Failed: {e}")
            return False

if __name__ == "__main__":
    # Test Sync
    logging.basicConfig(level=logging.INFO)
    bridge = OpenCTIBridge()
    if bridge.active:
        bridge.sync_purified_sightings()
    else:
        print("Bridge not active. Check credentials.")
