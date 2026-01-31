"""
MITRE ATT&CK TTP Mapper for SOC_Intelligence

Network traffic-based technique inference following Ultimate Prompt rules:
- Evidence-based only (no speculation)
- L3+ observable techniques only
- Confidence scoring
- Citations required
"""

import logging
from typing import List, Dict, Optional, Set
from collections import defaultdict

from src.unified.models.schemas import TTP, TOONEvent

logger = logging.getLogger(__name__)


class TTPMapper:
    """
    MITRE ATT&CK technique mapper for network-observable behaviors
    
    Follows Ultimate Prompt specification:
    - Map techniques only when TOON evidence directly supports
    - Confidence: HIGH / MEDIUM / LOW
    - No speculation beyond available evidence
    """
    
    # Network-observable MITRE techniques (from Ultimate Prompt)
    NETWORK_TECHNIQUES = {
        "T1595": {
            "name": "Active Scanning",
            "tactic": "Reconnaissance",
            "indicators": ["port_scan", "service_scan"]
        },
        "T1071": {
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "indicators": ["c2_pattern", "beaconing"]
        },
        "T1071.001": {
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "indicators": ["http_c2", "https_c2"]
        },
        "T1071.004": {
            "name": "Application Layer Protocol: DNS",
            "tactic": "Command and Control",
            "indicators": ["dns_tunneling", "dns_exfil"]
        },
        "T1573": {
            "name": "Encrypted Channel",
            "tactic": "Command and Control",
            "indicators": ["tls_c2", "custom_encryption"]
        },
        "T1573.002": {
            "name": "Encrypted Channel: Asymmetric Cryptography",
            "tactic": "Command and Control",
            "indicators": ["tls_direct_ip", "tls_no_sni"]
        },
        "T1046": {
            "name": "Network Service Scanning",
            "tactic": "Discovery",
            "indicators": ["port_scan", "service_enumeration"]
        },
        "T1021": {
            "name": "Remote Services",
            "tactic": "Lateral Movement",
            "indicators": ["rdp", "ssh", "smb"]
        },
        "T1048": {
            "name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "indicators": ["dns_exfil", "icmp_exfil"]
        },
        "T1041": {
            "name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "indicators": ["large_uploads", "sustained_egress"]
        }
    }
    
    def infer_techniques(self, events: List[TOONEvent]) -> List[TTP]:
        """
        Infer MITRE techniques from TOON events
        
        Returns:
            List of TTPs with evidence citations
        """
        
        detected_ttps = []
        
        # Analyze patterns
        patterns = self._detect_patterns(events)
        
        # Map patterns to techniques
        for technique_id, technique_info in self.NETWORK_TECHNIQUES.items():
            for indicator in technique_info["indicators"]:
                if indicator in patterns:
                    evidence = patterns[indicator]["evidence"]
                    confidence = patterns[indicator]["confidence"]
                    
                    ttp = TTP(
                        technique_id=technique_id,
                        technique_name=technique_info["name"],
                        tactic=technique_info["tactic"],
                        confidence=confidence,
                        evidence=evidence
                    )
                    detected_ttps.append(ttp)
        
        logger.info(f"Inferred {len(detected_ttps)} TTPs from {len(events)} events")
        return detected_ttps
    
    def _detect_patterns(self, events: List[TOONEvent]) -> Dict[str, Dict]:
        """
        Detect behavioral patterns in TOON events
        
        Returns:
            {pattern_name: {"evidence": [...], "confidence": "HIGH/MEDIUM/LOW"}}
        """
        patterns = {}
        
        # Pattern 1: Beaconing (T1071)
        beaconing = self._detect_beaconing(events)
        if beaconing:
            patterns["beaconing"] = beaconing
            patterns["c2_pattern"] = beaconing
        
        # Pattern 2: Port scanning (T1595, T1046)
        port_scan = self._detect_port_scan(events)
        if port_scan:
            patterns["port_scan"] = port_scan
        
        # Pattern 3: DNS tunneling (T1071.004)
        dns_tunnel = self._detect_dns_tunneling(events)
        if dns_tunnel:
            patterns["dns_tunneling"] = dns_tunnel
            patterns["dns_exfil"] = dns_tunnel
        
        # Pattern 4: TLS without SNI (T1573.002)
        tls_no_sni = self._detect_tls_no_sni(events)
        if tls_no_sni:
            patterns["tls_no_sni"] = tls_no_sni
            patterns["tls_direct_ip"] = tls_no_sni
        
        # Pattern 5: Lateral movement services (T1021)
        lateral = self._detect_lateral_movement(events)
        if lateral:
            patterns["rdp"] = lateral.get("rdp", {})
            patterns["ssh"] = lateral.get("ssh", {})
            patterns["smb"] = lateral.get("smb", {})
        
        return patterns
    
    def _detect_beaconing(self, events: List[TOONEvent]) -> Optional[Dict]:
        """
        Detect periodic beaconing pattern
        
        Evidence:
        - Fixed time intervals between connections
        - Same source/dest pair
        - Consistent payload sizes
        """
        if len(events) < 5:
            return None
        
        # Group by connection pairs
        connections = defaultdict(list)
        for event in events:
            if event.si and event.di:
                key = f"{event.si}->{event.di}:{event.dp}"
                connections[key].append(event.t)
        
        # Check for periodic patterns
        for conn, timestamps in connections.items():
            if len(timestamps) < 5:
                continue
            
            # Calculate intervals
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            # Check for consistency (±5%)
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)
                stddev = variance ** 0.5
                coefficient_of_variation = stddev / avg_interval if avg_interval > 0 else 1
                
                if coefficient_of_variation < 0.05:  # Very consistent
                    evidence = [
                        f"Connection: {conn}",
                        f"Beacons: {len(timestamps)}",
                        f"Interval: {avg_interval:.1f}s (±{stddev:.1f}s)",
                        f"Consistency: {(1-coefficient_of_variation)*100:.1f}%"
                    ]
                    
                    return {
                        "evidence": evidence,
                        "confidence": "HIGH"
                    }
        
        return None
    
    def _detect_port_scan(self, events: List[TOONEvent]) -> Optional[Dict]:
        """
        Detect port scanning activity
        
        Evidence:
        - Single source, multiple destinations/ports
        - Short time window
        - Minimal data transfer
        """
        if len(events) < 10:
            return None
        
        # Group by source IP
        sources = defaultdict(lambda: {"destinations": set(), "ports": set()})
        
        for event in events:
            if event.si and event.di:
                sources[event.si]["destinations"].add(event.di)
                if event.dp:
                    sources[event.si]["ports"].add(event.dp)
        
        # Check for scanning behavior
        for src, data in sources.items():
            if len(data["ports"]) > 20 or len(data["destinations"]) > 10:
                evidence = [
                    f"Source: {src}",
                    f"Unique destinations: {len(data['destinations'])}",
                    f"Unique ports: {len(data['ports'])}"
                ]
                
                confidence = "HIGH" if len(data["ports"]) > 50 else "MEDIUM"
                return {"evidence": evidence, "confidence": confidence}
        
        return None
    
    def _detect_dns_tunneling(self, events: List[TOONEvent]) -> Optional[Dict]:
        """Detect DNS tunneling indicators"""
        dns_events = [e for e in events if e.pr == "dns" and e.dns_query]
        
        if len(dns_events) < 10:
            return None
        
        # Check for suspicious patterns
        long_queries = [e for e in dns_events if len(e.dns_query) > 50]
        high_entropy_queries = []  # TODO: implement entropy check
        
        if len(long_queries) > 5:
            evidence = [
                f"Long DNS queries: {len(long_queries)}",
                f"Example: {long_queries[0].dns_query[:60]}..."
            ]
            return {"evidence": evidence, "confidence": "MEDIUM"}
        
        return None
    
    def _detect_tls_no_sni(self, events: List[TOONEvent]) -> Optional[Dict]:
        """Detect TLS connections without SNI (direct-to-IP C2)"""
        tls_events = [e for e in events if e.pr == "tls"]
        
        if not tls_events:
            return None
        
        no_sni = [e for e in tls_events if not e.tls_sni and e.di]
        
        if len(no_sni) > 3:
            evidence = [
                f"TLS connections without SNI: {len(no_sni)}",
                f"Destinations: {', '.join(set(e.di for e in no_sni[:5]))}"
            ]
            
            # Check for JA3 fingerprints
            ja3_present = [e for e in no_sni if e.tls_ja3]
            if ja3_present:
                evidence.append(f"JA3 fingerprints: {', '.join(set(e.tls_ja3 for e in ja3_present[:3]))}")
            
            return {"evidence": evidence, "confidence": "HIGH"}
        
        return None
    
    def _detect_lateral_movement(self, events: List[TOONEvent]) -> Dict[str, Dict]:
        """Detect lateral movement via RDP/SSH/SMB"""
        lateral_patterns = {}
        
        # RDP (port 3389)
        rdp_events = [e for e in events if e.dp == 3389 or e.sp == 3389]
        if len(rdp_events) > 2:
            lateral_patterns["rdp"] = {
                "evidence": [f"RDP connections: {len(rdp_events)}"],
                "confidence": "MEDIUM"
            }
        
        # SSH (port 22)
        ssh_events = [e for e in events if e.dp == 22 or e.sp == 22]
        if len(ssh_events) > 2:
            lateral_patterns["ssh"] = {
                "evidence": [f"SSH connections: {len(ssh_events)}"],
                "confidence": "MEDIUM"
            }
        
        # SMB (ports 445, 139)
        smb_events = [e for e in events if e.dp in [445, 139] or e.sp in [445, 139]]
        if len(smb_events) > 2:
            lateral_patterns["smb"] = {
                "evidence": [f"SMB connections: {len(smb_events)}"],
                "confidence": "MEDIUM"
            }
        
        return lateral_patterns
