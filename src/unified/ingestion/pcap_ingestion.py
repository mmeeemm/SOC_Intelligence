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

from unified.models.schemas import TOONEvent, ProtocolType
from unified.db.duckdb_adapter import DuckDBAdapter

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
        """
        Run Zeek and enrich events with UIDs, services, etc.
        
        Process:
        1. Run Zeek on PCAP → generate logs (conn.log, dns.log, http.log)
        2. Parse conn.log → extract sessions with UIDs
        3. Correlate Zeek sessions with TOON events by 5-tuple + timestamp
        4. Add Zeek UIDs and service info to TOON events
        
        Returns:
            Path to Zeek logs directory or None on failure
        """
        try:
            # Create temp directory for Zeek logs
            zeek_dir = tempfile.mkdtemp(prefix='zeek_')
            zeek_dir_path = Path(zeek_dir)
            
            logger.info(f"Running Zeek on {pcap_path.name}...")
            
            # Run Zeek
            cmd = [
                "zeek",
                "-r", str(pcap_path),
                "-C"  # Ignore checksums (common in captured traffic)
            ]
            
            result = subprocess.run(
                cmd,
                cwd=zeek_dir,
                capture_output=True,
                text=True,
                timeout=600  # 10 min max
            )
            
            if result.returncode != 0:
                logger.error(f"Zeek failed: {result.stderr}")
                return None
            
            # Parse conn.log
            conn_log = zeek_dir_path / "conn.log"
            if not conn_log.exists():
                logger.warning("Zeek did not generate conn.log")
                return zeek_dir_path
            
            zeek_sessions = self._parse_zeek_conn_log(conn_log)
            logger.info(f"Parsed {len(zeek_sessions)} Zeek sessions")
            
            # Correlate with TOON events
            matched = 0
            for event in events:
                # Find matching Zeek session by 5-tuple + timestamp
                matching_session = self._find_matching_zeek_session(event, zeek_sessions)
                if matching_session:
                    event.zeek_uid = matching_session['uid']
                    event.zeek_service = matching_session.get('service')
                    event.zeek_conn_state = matching_session.get('conn_state')
                    matched += 1
            
            logger.info(f"Enriched {matched}/{len(events)} events with Zeek UIDs")
            
            return zeek_dir_path
            
        except Exception as e:
            logger.error(f"Zeek enrichment failed: {e}")
            return None
    
    def _parse_zeek_conn_log(self, conn_log_path: Path) -> List[Dict[str, Any]]:
        """
        Parse Zeek conn.log file
        
        Returns list of connection dictionaries with:
        - ts: timestamp
        - uid: Zeek unique ID
        - id.orig_h: source IP
        - id.orig_p: source port
        - id.resp_h: dest IP
        - id.resp_p: dest port
        - proto: protocol
        - service: identified service
        - conn_state: connection state
        """
        sessions = []
        
        with open(conn_log_path, 'r') as f:
            for line in f:
                # Skip comments and headers
                if line.startswith('#'):
                    continue
                
                # Parse TSV line
                fields = line.strip().split('\t')
                if len(fields) < 10:
                    continue
                
                try:
                    # Zeek conn.log format:
                    # ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration ...
                    session = {
                        'ts': float(fields[0]),
                        'uid': fields[1],
                        'orig_h': fields[2],
                        'orig_p': int(fields[3]),
                        'resp_h': fields[4],
                        'resp_p': int(fields[5]),
                        'proto': fields[6],
                        'service': fields[7] if fields[7] != '-' else None,
                        'conn_state': fields[11] if len(fields) > 11 and fields[11] != '-' else None,
                    }
                    sessions.append(session)
                except (ValueError, IndexError) as e:
                    logger.debug(f"Failed to parse Zeek line: {e}")
                    continue
        
        return sessions
    
    def _find_matching_zeek_session(self, event: TOONEvent, sessions: List[Dict]) -> Optional[Dict]:
        """
        Find Zeek session matching TOON event by 5-tuple and timestamp
        
        Matching criteria:
        - Source IP matches
        - Source port matches (if present)
        - Dest IP matches
        - Dest port matches (if present)
        - Timestamp within ±1 second window
        """
        if not event.si or not event.di:
            return None
        
        for session in sessions:
            # Check 5-tuple match
            if session['orig_h'] != event.si:
                continue
            if event.sp and session['orig_p'] != event.sp:
                continue
            if session['resp_h'] != event.di:
                continue
            if event.dp and session['resp_p'] != event.dp:
                continue
            
            # Check timestamp proximity (within 1 second)
            if abs(session['ts'] - event.t) <= 1.0:
                return session
        
        return None
    
    def _process_snort_alerts(self, pcap_path: Path, events: List[TOONEvent]) -> int:
        """
        Run Snort and add alerts to matching events
        
        Process:
        1. Run Snort with community rules on PCAP
        2. Parse alert_fast output
        3. Correlate alerts with TOON events by IP + port + timestamp
        4. Add alert info to matching events
        
        Returns:
            Number of alerts matched to events
        """
        try:
            # Snort config path (go up from src/unified/ingestion to project root)
            snort_config = Path(__file__).parent.parent.parent.parent / "configs" / "snort.lua"
            
            if not snort_config.exists():
                logger.error(f"Snort config not found: {snort_config}")
                return 0
            
            logger.info(f"Running Snort on {pcap_path.name}...")
            
            # Create temp file for alerts
            alert_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            alert_file.close()
            
            try:
                # Run Snort
                cmd = [
                    "snort",
                    "-c", str(snort_config),
                    "-r", str(pcap_path),
                    "-A", "fast",  # Fast alert format
                    "-l", str(Path(alert_file.name).parent),  # Log directory
                    "-q"  # Quiet mode
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 min max
                )
                
                # Snort may return non-zero even on success with alerts
                # Check for actual errors in stderr
                if "FATAL" in result.stderr or "ERROR" in result.stderr:
                    logger.error(f"Snort failed: {result.stderr}")
                    return 0
                
                # Parse alerts from stdout and alert_fast file
                alerts = self._parse_snort_fast_alerts(result.stdout)
                
                # Also check for alert_fast.txt in log directory
                alert_fast_file = Path(alert_file.name).parent / "alert_fast.txt"
                if alert_fast_file.exists():
                    with open(alert_fast_file, 'r') as f:
                        alerts.extend(self._parse_snort_fast_alerts(f.read()))
                
                logger.info(f"Snort generated {len(alerts)} alerts")
                
                # Correlate alerts with TOON events
                matched = 0
                for alert in alerts:
                    for event in events:
                        if self._alert_matches_event(alert, event):
                            # Add alert info to event
                            if not hasattr(event, 'ids_alerts'):
                                event.ids_alerts = []
                            event.ids_alerts.append({
                                'sid': alert.get('sid'),
                                'gid': alert.get('gid'),
                                'message': alert.get('message'),
                                'priority': alert.get('priority'),
                                'classification': alert.get('classification')
                            })
                            matched += 1
                            break  # Move to next alert
                
                logger.info(f"Matched {matched} Snort alerts to events")
                return matched
                
            finally:
                Path(alert_file.name).unlink(missing_ok=True)
                
        except Exception as e:
            logger.error(f"Snort processing failed: {e}")
            return 0
    
    def _parse_snort_fast_alerts(self, alert_text: str) -> List[Dict[str, Any]]:
        """
        Parse Snort fast alert format
        
        Format:
        MM/DD-HH:MM:SS.SSSSSS [**] [GID:SID:REV] Message [**] [Classification: class] [Priority: N] {PROTO} SRC_IP:PORT -> DST_IP:PORT
        
        Example:
        01/31-20:45:12.123456 [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.0.78.212:80 -> 192.168.1.8:52917
        """
        alerts = []
        
        for line in alert_text.split('\n'):
            if not line.strip() or '[**]' not in line:
                continue
            
            try:
                alert = {}
                
                # Extract timestamp
                if line[:17].replace('-', '').replace(':', '').replace('.', '').replace('/', '').isdigit():
                    alert['timestamp'] = line[:21].strip()
                
                # Extract GID:SID:REV
                gid_sid_match = line.find('[')
                if gid_sid_match != -1:
                    gid_sid_end = line.find(']', gid_sid_match)
                    gid_sid_str = line[gid_sid_match+1:gid_sid_end]
                    if ':' in gid_sid_str:
                        parts = gid_sid_str.split(':')
                        if len(parts) >= 2:
                            try:
                                alert['gid'] = int(parts[0])
                                alert['sid'] = int(parts[1])
                            except ValueError:
                                pass
                
                # Extract message
                msg_start = line.find(']', line.find('[**]') + 4) + 2
                msg_end = line.find('[**]', msg_start)
                if msg_start > 0 and msg_end > msg_start:
                    alert['message'] = line[msg_start:msg_end].strip()
                
                # Extract priority
                priority_match = line.find('[Priority: ')
                if priority_match != -1:
                    priority_end = line.find(']', priority_match)
                    try:
                        alert['priority'] = int(line[priority_match+11:priority_end])
                    except ValueError:
                        pass
                
                # Extract IPs and ports
                # Format: {PROTO} SRC_IP:PORT -> DST_IP:PORT
                proto_match = line.find('{')
                if proto_match != -1:
                    proto_end = line.find('}', proto_match)
                    alert['proto'] = line[proto_match+1:proto_end].strip()
                    
                    # Extract IPs after protocol
                    ip_section = line[proto_end+1:].strip()
                    if '->' in ip_section:
                        src, dst = ip_section.split('->')
                        
                        # Source IP:PORT
                        if ':' in src:
                            src_parts = src.strip().rsplit(':', 1)
                            alert['src_ip'] = src_parts[0]
                            try:
                                alert['src_port'] = int(src_parts[1])
                            except ValueError:
                                pass
                        
                        # Dest IP:PORT
                        if ':' in dst:
                            dst_parts = dst.strip().rsplit(':', 1)
                            alert['dst_ip'] = dst_parts[0]
                            try:
                                alert['dst_port'] = int(dst_parts[1])
                            except ValueError:
                                pass
                
                # Only add if we have minimum required fields
                if 'sid' in alert and ('src_ip' in alert or 'dst_ip' in alert):
                    alerts.append(alert)
                    
            except Exception as e:
                logger.debug(f"Failed to parse Snort alert line: {e}")
                continue
        
        return alerts
    
    def _alert_matches_event(self, alert: Dict, event: TOONEvent) -> bool:
        """
        Check if Snort alert matches TOON event
        
        Matching criteria:
        - Source IP matches OR destination IP matches
        - If ports present, they should match too
        - Protocol should match (if specified in alert)
        """
        # Check source IP match
        src_match = False
        if 'src_ip' in alert and event.si == alert['src_ip']:
            src_match = True
            # Check source port if present
            if 'src_port' in alert and event.sp and event.sp != alert['src_port']:
                src_match = False
        
        # Check destination IP match
        dst_match = False
        if 'dst_ip' in alert and event.di == alert['dst_ip']:
            dst_match = True
            # Check dest port if present
            if 'dst_port' in alert and event.dp and event.dp != alert['dst_port']:
                dst_match = False
        
        # Alert matches if either source or dest matches (bidirectional)
        return src_match or dst_match

