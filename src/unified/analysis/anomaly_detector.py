"""
ML-Based Anomaly Detection for SOC_Intelligence

Statistical and machine learning-based anomaly detection:
- Behavioral baselines
- Beaconing detection
- DNS tunneling detection
- Port scan detection
- Volume anomalies
"""

import logging
from typing import List, Dict, Optional, Tuple
from collections import defaultdict, Counter
import math

from src.unified.models.schemas import TOONEvent

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Machine Learning-based anomaly detection for network traffic
    
    Features:
    - Statistical baselines
    - Behavioral anomaly detection
    - Pattern recognition (beaconing, tunneling, scanning)
    - No speculation (evidence-based)
    """
    
    def __init__(self):
        self.baseline = None
        self.trained = False
    
    def detect_anomalies(self, events: List[TOONEvent]) -> Dict[str, any]:
        """
        Detect anomalies in TOON events
        
        Returns:
            {
                "beaconing": [...],
                "dns_tunneling": [...],
                "port_scans": [...],
                "volume_anomalies": [...],
                "total_anomalies": int
            }
        """
        
        results = {
            "beaconing": [],
            "dns_tunneling": [],
            "port_scans": [],
            "volume_anomalies": [],
            "protocol_anomalies": [],
            "total_anomalies": 0
        }
        
        if len(events) < 10:
            logger.warning("Insufficient events for anomaly detection")
            return results
        
        # Detect each type
        results["beaconing"] = self._detect_beaconing(events)
        results["dns_tunneling"] = self._detect_dns_tunneling(events)
        results["port_scans"] = self._detect_port_scans(events)
        results["volume_anomalies"] = self._detect_volume_anomalies(events)
        results["protocol_anomalies"] = self._detect_protocol_anomalies(events)
        
        results["total_anomalies"] = sum(len(v) if isinstance(v, list) else 0 for v in results.values())
        
        logger.info(f"Detected {results['total_anomalies']} anomalies")
        return results
    
    def _detect_beaconing(self, events: List[TOONEvent]) -> List[Dict]:
        """
        Detect beaconing patterns (periodic C2 communication)
        
        Method: Analyze inter-arrival times for periodicity
        """
        beacons = []
        
        # Group by connection pairs
        connections = defaultdict(list)
        for event in events:
            if event.si and event.di:
                key = (event.si, event.di, event.dp)
                connections[key].append(event.t)
        
        # Analyze each connection for periodicity
        for (src, dst, port), timestamps in connections.items():
            if len(timestamps) < 5:
                continue
            
            timestamps.sort()
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if not intervals:
                continue
            
            # Statistical analysis
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((i - mean_interval)**2 for i in intervals) / len(intervals)
            stddev = math.sqrt(variance)
            
            # Coefficient of variation (should be low for beaconing)
            cv = stddev / mean_interval if mean_interval > 0 else 1
            
            # Entropy (should be low for beaconing)
            entropy = self._calculate_entropy([round(i) for i in intervals])
            
            # Detect beaconing: low CV + low entropy + reasonable interval
            if cv < 0.1 and entropy < 1.5 and 1 < mean_interval < 3600:
                beacons.append({
                    "src": src,
                    "dst": dst,
                    "port": port,
                    "interval_avg": round(mean_interval, 2),
                    "interval_stddev": round(stddev, 2),
                    "beacons_count": len(timestamps),
                    "coefficient_variation": round(cv, 4),
                    "entropy": round(entropy, 2),
                    "confidence": "HIGH" if cv < 0.05 else "MEDIUM",
                    "details": f"Fixed {mean_interval:.1f}s interval (±{stddev:.1f}s) over {len(timestamps)} beacons"
                })
        
        return beacons
    
    def _detect_dns_tunneling(self, events: List[TOONEvent]) -> List[Dict]:
        """
        Detect DNS tunneling attempts
        
        Indicators:
        - Unusually long DNS queries
        - High query volume to same domain
        - High entropy in subdomain
        - Uncommon query types
        """
        tunnels = []
        dns_events = [e for e in events if e.pr == "dns" and e.dns_query]
        
        if len(dns_events) < 5:
            return tunnels
        
        # Analyze queries
        for event in dns_events:
            query = event.dns_query
            query_length = len(query)
            
            # Indicator 1: Unusually long queries
            if query_length > 50:
                # Calculate entropy
                entropy = self._calculate_string_entropy(query)
                
                # High entropy + long query = tunneling
                if entropy > 3.5:
                    tunnels.append({
                        "src": event.si,
                        "query": query[:60] + "..." if len(query) > 60 else query,
                        "query_length": query_length,
                        "entropy": round(entropy, 2),
                        "confidence": "HIGH" if entropy > 4.0 else "MEDIUM",
                        "indicator": "Long query with high entropy"
                    })
        
        # Group by domain for frequency analysis
        domain_counts = Counter(e.dns_query.split('.')[-2:][0] if '.' in e.dns_query else e.dns_query 
                               for e in dns_events)
        
        for domain, count in domain_counts.items():
            if count > 20:  # Excessive queries
                tunnels.append({
                    "domain": domain,
                    "query_count": count,
                    "confidence": "MEDIUM",
                    "indicator": "Excessive DNS queries to same domain"
                })
        
        return tunnels
    
    def _detect_port_scans(self, events: List[TOONEvent]) -> List[Dict]:
        """
        Detect port scanning activity
        
        Indicators:
        - Single source, many destinations/ports
        - High connection rate
        - Minimal data transfer
        """
        scans = []
        
        # Group by source
        sources = defaultdict(lambda: {
            "destinations": set(),
            "dest_ports": set(),
            "connections": 0,
            "timestamps": []
        })
        
        for event in events:
            if event.si and event.di:
                sources[event.si]["destinations"].add(event.di)
                if event.dp:
                    sources[event.si]["dest_ports"].add(event.dp)
                sources[event.si]["connections"] += 1
                sources[event.si]["timestamps"].append(event.t)
        
        # Analyze each source
        for src, data in sources.items():
            num_ports = len(data["dest_ports"])
            num_dests = len(data["destinations"])
            
            # Scanning indicators
            if num_ports > 20:  # Port scan
                timestamps = sorted(data["timestamps"])
                duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
                rate = data["connections"] / duration if duration > 0 else 0
                
                scans.append({
                    "src": src,
                    "type": "port_scan",
                    "unique_ports": num_ports,
                    "unique_destinations": num_dests,
                    "connections": data["connections"],
                    "duration": round(duration, 2),
                    "rate_per_second": round(rate, 2),
                    "confidence": "HIGH" if num_ports > 50 else "MEDIUM"
                })
            
            elif num_dests > 15:  # Network scan
                scans.append({
                    "src": src,
                    "type": "network_scan",
                    "unique_destinations": num_dests,
                    "unique_ports": num_ports,
                    "connections": data["connections"],
                    "confidence": "MEDIUM"
                })
        
        return scans
    
    def _detect_volume_anomalies(self, events: List[TOONEvent]) -> List[Dict]:
        """
        Detect volume-based anomalies
        
        Indicators:
        - Unusually large data transfers
        - High connection rate
        """
        anomalies = []
        
        # Analyze per-connection volumes
        connections = defaultdict(lambda: {
            "bytes_sent": 0,
            "bytes_recv": 0,
            "packets": 0
        })
        
        for event in events:
            if event.si and event.di:
                key = (event.si, event.di, event.dp)
                connections[key]["bytes_sent"] += event.bytes_sent or 0
                connections[key]["bytes_recv"] += event.bytes_recv or 0
                connections[key]["packets"] += 1
        
        # Find outliers (simple threshold-based for now)
        for (src, dst, port), data in connections.items():
            total_bytes = data["bytes_sent"] + data["bytes_recv"]
            
            # Large transfer
            if total_bytes > 100_000_000:  # > 100MB
                anomalies.append({
                    "src": src,
                    "dst": dst,
                    "port": port,
                    "total_bytes": total_bytes,
                    "bytes_sent": data["bytes_sent"],
                    "bytes_recv": data["bytes_recv"],
                    "type": "large_transfer",
                    "confidence": "MEDIUM"
                })
        
        return anomalies
    
    def _detect_protocol_anomalies(self, events: List[TOONEvent]) -> List[Dict]:
        """Detect unusual protocol usage"""
        anomalies = []
        
        # Count protocols
        protocols = Counter(e.pr for e in events)
        total = len(events)
        
        # Protocol 1: ICMP usage (unusual in most environments)
        icmp_count = protocols.get("icmp", 0)
        if icmp_count > 10 and (icmp_count / total) > 0.05:
            anomalies.append({
                "protocol": "icmp",
                "count": icmp_count,
                "percentage": round(icmp_count / total * 100, 2),
                "indicator": "Unusual ICMP traffic volume",
                "confidence": "MEDIUM"
            })
        
        return anomalies
    
    def _calculate_entropy(self, values: List) -> float:
        """Calculate Shannon entropy of a list"""
        if not values:
            return 0.0
        
        counts = Counter(values)
        total = len(values)
        
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_string_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not s:
            return 0.0
        
        counts = Counter(s)
        length = len(s)
        
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
