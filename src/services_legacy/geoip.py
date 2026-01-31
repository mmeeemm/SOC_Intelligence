
"""
GeoIP Enrichment Service
Enriches IP addresses with geographic location data.
"""

import pandas as pd
import zipfile
import os
import logging
from typing import Optional, Dict, Tuple
from functools import lru_cache
import ipaddress

logger = logging.getLogger("BLINK.GeoIP")

class GeoIPService:
    """
    GeoIP lookup service using MaxMind GeoLite2 CSV data.
    """

    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or os.path.expanduser("~/Downloads")
        self.country_blocks_v4 = None
        self.country_locations = None
        self._loaded = False

    def load(self) -> bool:
        """Load GeoIP databases from CSV files."""
        if self._loaded:
            return True

        try:
            # Try to load Country data
            country_zip = os.path.join(self.data_dir, "GeoLite2-Country-CSV_20251212.zip")

            if os.path.exists(country_zip):
                logger.info(f"Loading GeoIP Country data from {country_zip}")
                with zipfile.ZipFile(country_zip, 'r') as z:
                    blocks_file = [f for f in z.namelist() if 'Blocks-IPv4' in f and f.endswith('.csv')]
                    locations_file = [f for f in z.namelist() if 'Locations-en' in f and f.endswith('.csv')]

                    if blocks_file:
                        with z.open(blocks_file[0]) as f:
                            self.country_blocks_v4 = pd.read_csv(f, low_memory=False)
                    
                    if locations_file:
                        with z.open(locations_file[0]) as f:
                            self.country_locations = pd.read_csv(f, low_memory=False)

                self._loaded = True
                return True
            else:
                logger.warning(f"GeoIP Country data not found at {country_zip}")
                return False

        except Exception as e:
            logger.error(f"Failed to load GeoIP data: {e}")
            return False

    @lru_cache(maxsize=10000)
    def lookup_ip(self, ip: str) -> Optional[Dict]:
        """
        Look up geographic information for an IP address.
        """
        if not self._loaded:
            self.load()

        if not self._loaded or self.country_blocks_v4 is None:
            return None

        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return {"country_code": "PRIVATE", "country_name": "Private Network", "is_external": False}

            # Simple linear search (for demonstration/small datasets)
            # production should use a more efficient data structure
            for _, row in self.country_blocks_v4.iterrows():
                try:
                    network = ipaddress.ip_network(row['network'], strict=False)
                    if ip_obj in network:
                        geoname_id = row.get('geoname_id') or row.get('registered_country_geoname_id')
                        if pd.notna(geoname_id) and self.country_locations is not None:
                            loc = self.country_locations[self.country_locations['geoname_id'] == int(geoname_id)]
                            if not loc.empty:
                                return {
                                    "country_code": loc.iloc[0].get('country_iso_code', 'XX'),
                                    "country_name": loc.iloc[0].get('country_name', 'Unknown'),
                                    "is_external": True
                                }
                        break
                except:
                    continue

            return {"country_code": "XX", "country_name": "Unknown", "is_external": True}

        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            return None

    def enrich_dataframe(self, df: pd.DataFrame, ip_column: str = 'destination.ip') -> pd.DataFrame:
        """
        Enrich a dataframe with GeoIP data.
        """
        if df.empty or ip_column not in df.columns:
            return df

        if not self._loaded:
            self.load()

        if not self._loaded:
            return df

        unique_ips = df[ip_column].dropna().unique()
        geo_data = {str(ip): self.lookup_ip(str(ip)) for ip in unique_ips[:500]}

        df = df.copy()
        df['geo.country_code'] = df[ip_column].astype(str).map(lambda x: (geo_data.get(x) or {}).get('country_code', 'XX'))
        df['geo.country_name'] = df[ip_column].astype(str).map(lambda x: (geo_data.get(x) or {}).get('country_name', 'Unknown'))
        df['geo.is_external'] = df[ip_column].astype(str).map(lambda x: (geo_data.get(x) or {}).get('is_external', False))

        return df

# Singleton instance
_geoip_service = None

def get_geoip_service() -> GeoIPService:
    global _geoip_service
    if _geoip_service is None:
        _geoip_service = GeoIPService()
    return _geoip_service

def enrich_with_geoip(df: pd.DataFrame, ip_column: str = 'destination.ip') -> pd.DataFrame:
    service = get_geoip_service()
    return service.enrich_dataframe(df, ip_column)
