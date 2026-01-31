"""
Unified PCAP Ingestion Engine for SOC_Intelligence

Combines:
- PyShark/TShark extraction (One_Blink)
- TOON normalization (Ultimate Prompt rules)
- Zeek enrichment
- Snort integration
- Optimized for speed and data quality
"""

import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any
import csv
import logging
from datetime import datetime
import json

from src.unified.models.schemas import TOONEvent, ProtocolType
from src.unified.db.duckdb_adapter import DuckDBAdapter

logger = logging.getLogger(__name__)


class PCAPIngestionEngine:
    """
    Optimized PCAP ingestion following Ultimate Prompt spec:
    - L3+ only (no L1/L2)
    - TOON normalization
    - Null/placeholder filtering
    - Fast processing
    """
    
    def __init__(self, db: DuckDBAdapter):
        self.db = db
        self.zeek_enabled = self._check_zeek()
        self.snort_enabled = self._check_snort()
    
    def _check_zeek(self) -> bool:
        """Check if Zeek is available"""
        try:
            result = subprocess.run(['zeek', '--version'], capture_output=True, timeout=2)
            available = result.returncode == 0
            if available:
                logger.info("Zeek is available for enrichment")
            return available
        except:
            logger.warning("Zeek not found - enrichment disabled")
            return False
    
    def _check_snort(self) -> bool:
        """Check if Snort is available"""
        try:
            result = subprocess.run(['snort', '--version'], capture_output=True, timeout=2)
            available = result.returncode == 0
            if available:
                logger.info("Snort is available for IDS alerts")
            return available
        except:
            logger.warning("Snort not found - IDS alerts disabled")
            return False
    
    def ingest_pcap(
        self,
        pcap_path: Path,
        enable_zeek: bool = True,
        enable_snort: bool = True
    ) -> Dict[str, Any]:
        """
        Main ingestion pipeline
        
        Returns:
            {
                "events_extracted": int,
                "events_normalized": int,
                "events_inserted": int,
                "processing_time": float,
                "zeek_logs": Path or None,
                "snort_alerts": int
            }
        """
        start_time = datetime.now()
        logger.info(f"Starting PCAP ingestion: {pcap_path.name}")
        
        # Step 1: TShark extraction (L3+ only)
        logger.info("Step 1/4: TShark extraction...")
        raw_events = self._extract_with_tshark(pcap_path)
        logger.info(f"Extracted {len(raw_events)} raw events")
        
        # Step 2: TOON normalization
        logger.info("Step 2/4: TOON normalization...")
        toon_events = self._normalize_to_toon(raw_events, pcap_path.name)
        logger.info(f"Normalized to {len(toon_events)} TOON events")
        
        # Step 3: Zeek enrichment (optional)
        zeek_logs = None
        if enable_zeek and self.zeek_enabled:
            logger.info("Step 3/4: Zeek enrichment...")
            zeek_logs = self._enrich_with_zeek(pcap_path, toon_events)
        else:
            logger.info("Step 3/4: Zeek enrichment skipped")
        
        # Step 4: Snort alerts (optional)
        snort_alerts = 0
        if enable_snort and self.snort_enabled:
            logger.info("Step 4/4: Snort IDS analysis...")
            snort_alerts = self._process_snort_alerts(pcap_path, toon_events)
        else:
            logger.info("Step 4/4: Snort analysis skipped")
        
        # Insert into database
        logger.info("Inserting events into DuckDB...")
        inserted = self.db.insert_events(toon_events)
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        result = {
            "events_extracted": len(raw_events),
            "events_normalized": len(toon_events),
            "events_inserted": inserted,
            "processing_time": processing_time,
            "zeek_logs": zeek_logs,
            "snort_alerts": snort_alerts
        }
        
        logger.info(f"Ingestion complete: {inserted} events in {processing_time:.2f}s")
        return result
    
    def _extract_with_tshark(self, pcap_path: Path) -> List[Dict[str, Any]]:
        """
        Extract L3+ fields using TShark
        
        Optimizations:
        - Disable name resolution (-n)
        - CSV output for speed
        - Only necessary fields
        - First occurrence only (-E occurrence=f)
        """
        
        # TShark command (L3+ only, optimized)
        cmd = [
            "tshark", "-r", str(pcap_path),
            "-n",  # No name resolution (speed)
            "-T", "fields",
            
            # L3: IP
            "-e", "frame.time_epoch",
            "-e", "ip.src", "-e", "ipv6.src",
            "-e", "ip.dst", "-e", "ipv6.dst",
            "-e", "ip.proto",
            "-e", "ip.len",
            
            # L4: TCP/UDP
            "-e", "tcp.srcport", "-e", "udp.srcport",
            "-e", "tcp.dstport", "-e", "udp.dstport",
            "-e", "tcp.flags.str",
            "-e", "tcp.len", "-e", "udp.length",
            
            # L7: Protocols
            "-e", "_ws.col.Protocol",
            
            # DNS
            "-e", "dns.qry.name",
            "-e", "dns.qry.type",
            "-e", "dns.resp.name",
            
            # HTTP
            "-e", "http.request.method",
            "-e", "http.host",
            "-e", "http.request.uri",
            "-e", "http.user_agent",
            "-e", "http.response.code",
            
            # TLS/SSL
            "-e", "tls.handshake.extensions_server_name",
            "-e", "tls.handshake.ja3",
            "-e", "tls.record.version",
            
            # Output format
            "-E", "header=y",
            "-E", "separator=,",
            "-E", "quote=d",
            "-E", "occurrence=f"  # First occurrence only
        ]
        
        # Execute TShark
        temp_csv = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
        try:
            result = subprocess.run(
                cmd,
                stdout=temp_csv,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,  # 5 min max
                check=False
            )
            temp_csv.close()
            
            if result.returncode != 0:
                logger.error(f"TShark failed: {result.stderr}")
                raise RuntimeError(f"TShark extraction failed: {result.stderr}")
            
            # Parse CSV
            events = []
            with open(temp_csv.name, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    events.append(row)
            
            return events
            
        finally:
            Path(temp_csv.name).unlink(missing_ok=True)
    
    def _normalize_to_toon(self, raw_events: List[Dict], source_file: str) -> List[TOONEvent]:
        """
        Normalize raw TShark output to TOON schema
        
        Rules from Ultimate Prompt:
        - Drop null/placeholder values (0.0.0.0, port 0, empty strings)
        - L3+ only
        - Clean protocol names
        - Evidence-based only (no inference)
        """
        toon_events = []
        
        for raw in raw_events:
            try:
                # Timestamp (required)
                if not raw.get('frame.time_epoch'):
                    continue
                
                t = float(raw['frame.time_epoch'])
                
                # Source IP (prefer IPv4, fallback to IPv6)
                si = raw.get('ip.src') or raw.get('ipv6.src')
                if si in ['0.0.0.0', '::', '', None]:
                    si = None
                
                # Destination IP
                di = raw.get('ip.dst') or raw.get('ipv6.dst')
                if di in ['0.0.0.0', '::', '', None]:
                    di = None
                
                # Source port (TCP or UDP)
                sp_str = raw.get('tcp.srcport') or raw.get('udp.srcport')
                sp = int(sp_str) if sp_str  and sp_str != '0' else None
                
                # Destination port
                dp_str = raw.get('tcp.dstport') or raw.get('udp.dstport')
                dp = int(dp_str) if dp_str and dp_str != '0' else None
                
                # Protocol (normalize)
                pr = raw.get('_ws.col.Protocol', 'unknown').lower()
                
                # Build TOON event
                event = TOONEvent(
                    t=t,
                    si=si,
                    sp=sp,
                    di=di,
                    dp=dp,
                    pr=pr,
                    source_file=source_file
                )
                
                # Add optional fields if present
                if raw.get('dns.qry.name'):
                    event.dns_query = raw['dns.qry.name']
                
                if raw.get('http.request.method'):
                    event.http_method = raw['http.request.method']
                
                if raw.get('http.host'):
                    event.http_host = raw['http.host']
                
                if raw.get('http.user_agent'):
                    event.http_user_agent = raw['http.user_agent']
                
                if raw.get('http.response.code'):
                    event.http_status = int(raw['http.response.code'])
                
                if raw.get('tls.handshake.extensions_server_name'):
                    event.tls_sni = raw['tls.handshake.extensions_server_name']
                
                if raw.get('tls.handshake.ja3'):
                    event.tls_ja3 = raw['tls.handshake.ja3']
                
                toon_events.append(event)
                
            except Exception as e:
                logger.warning(f"Failed to normalize event: {e}")
                continue
        
        return toon_events
    
    def _enrich_with_zeek(self, pcap_path: Path, events: List[TOONEvent]) -> Optional[Path]:
        """Run Zeek and enrich events with UIDs, services, etc."""
        # TODO: Implement Zeek enrichment
        # For now, placeholder
        logger.warning("Zeek enrichment not yet implemented")
        return None
    
    def _process_snort_alerts(self, pcap_path: Path, events: List[TOONEvent]) -> int:
        """Run Snort and add alerts to matching events"""
        # TODO: Implement Snort integration
        # For now, placeholder
        logger.warning("Snort integration not yet implemented")
        return 0
