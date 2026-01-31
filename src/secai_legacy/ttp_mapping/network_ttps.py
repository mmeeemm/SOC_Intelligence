"""
Network-Inferred TTP Mapping

Maps observed network behaviors to MITRE ATT&CK techniques.
Only infers TTPs from network traffic - no endpoint assumptions.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ObservedTTP:
    """A detected TTP with justification and confidence."""
    technique_id: str
    technique_name: str
    justification: str
    confidence: float  # 0.0 to 1.0


# MITRE ATT&CK Network-Observable Techniques
NETWORK_TTPS = {
    # Command and Control
    'T1071.001': {
        'name': 'Application Layer Protocol: Web Protocols',
        'indicators': ['http', 'https', 'unusual_http_patterns']
    },
    'T1071.004': {
        'name': 'Application Layer Protocol: DNS',
        'indicators': ['dns_tunneling', 'high_dns_entropy', 'txt_queries']
    },
    'T1571': {
        'name': 'Non-Standard Port',
        'indicators': ['unusual_port_protocol', 'http_on_non_80', 'tls_on_non_443']
    },
    'T1573.001': {
        'name': 'Encrypted Channel: Symmetric Cryptography',
        'indicators': ['encrypted_c2', 'custom_encryption']
    },
    'T1573.002': {
        'name': 'Encrypted Channel: Asymmetric Cryptography',
        'indicators': ['tls_c2', 'ssl_to_malicious']
    },
    'T1572': {
        'name': 'Protocol Tunneling',
        'indicators': ['dns_tunneling', 'http_tunneling', 'icmp_tunneling']
    },
    'T1095': {
        'name': 'Non-Application Layer Protocol',
        'indicators': ['raw_socket', 'icmp_c2', 'custom_protocol']
    },
    
    # Exfiltration
    'T1041': {
        'name': 'Exfiltration Over C2 Channel',
        'indicators': ['high_outbound_volume', 'large_uploads', 'burst_traffic']
    },
    'T1048.001': {
        'name': 'Exfiltration Over Alternative Protocol: Symmetric Encrypted Non-C2 Protocol',
        'indicators': ['ftp_exfil', 'smtp_large_attachments']
    },
    'T1048.002': {
        'name': 'Exfiltration Over Alternative Protocol: Asymmetric Encrypted Non-C2 Protocol',
        'indicators': ['https_exfil', 'sftp_exfil']
    },
    'T1048.003': {
        'name': 'Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol',
        'indicators': ['http_exfil', 'dns_exfil', 'ftp_cleartext']
    },
    
    # Discovery
    'T1046': {
        'name': 'Network Service Discovery',
        'indicators': ['port_scan', 'service_enumeration', 'multi_port_connection']
    },
    'T1018': {
        'name': 'Remote System Discovery',
        'indicators': ['network_sweep', 'arp_scan', 'ping_sweep']
    },
    
    # Lateral Movement
    'T1021.001': {
        'name': 'Remote Services: Remote Desktop Protocol',
        'indicators': ['rdp_connection', 'rdp_brute_force']
    },
    'T1021.004': {
        'name': 'Remote Services: SSH',
        'indicators': ['ssh_connection', 'ssh_brute_force']
    },
    'T1021.002': {
        'name': 'Remote Services: SMB/Windows Admin Shares',
        'indicators': ['smb_connection', 'admin_share_access']
    },
    
    # Initial Access
    'T1566.001': {
        'name': 'Phishing: Spearphishing Attachment',
        'indicators': ['smtp_attachment', 'suspicious_attachment']
    },
    'T1566.002': {
        'name': 'Phishing: Spearphishing Link',
        'indicators': ['smtp_link', 'malicious_url_in_email']
    },
    
    # Resource Development
    'T1583.001': {
        'name': 'Acquire Infrastructure: Domains',
        'indicators': ['newly_registered_domain', 'dga_domain']
    },
}


class NetworkTTPMapper:
    """
    Maps network observations to MITRE ATT&CK techniques.
    
    This mapper only infers TTPs from network traffic observations.
    It does not make assumptions about endpoint behavior.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize mapper with optional configuration.
        
        Args:
            config: Optional configuration for thresholds
        """
        self.config = config or {}
        
        # Thresholds
        self.dns_entropy_threshold = self.config.get('dns_entropy_threshold', 3.5)
        self.high_volume_threshold = self.config.get('high_volume_mb', 100)
        self.beaconing_regularity = self.config.get('beaconing_regularity', 0.9)
    
    def infer_ttps(self, aggregates: Dict[str, Any], 
                   historical_stats: Optional[Dict[str, Any]] = None) -> List[ObservedTTP]:
        """
        Infer TTPs from aggregated network observations.
        
        Args:
            aggregates: Aggregated Zeek log data
            historical_stats: Optional historical ticket statistics
            
        Returns:
            List of 3-6 most relevant TTPs with justifications
        """
        detected_ttps: List[ObservedTTP] = []
        
        # Analyze protocol coverage
        protocols = aggregates.get('protocol_coverage', [])
        protocol_names = [p.get('protocol', '').upper() for p in protocols]
        
        # Check for DNS-based TTPs
        if 'DNS' in protocol_names:
            dns_ttps = self._analyze_dns(aggregates)
            detected_ttps.extend(dns_ttps)
        
        # Check for HTTP/HTTPS TTPs
        if any(p in protocol_names for p in ['HTTP', 'HTTPS', 'TLS/SSL']):
            http_ttps = self._analyze_http_tls(aggregates)
            detected_ttps.extend(http_ttps)
        
        # Check for email-based TTPs
        if 'SMTP' in protocol_names:
            smtp_ttps = self._analyze_smtp(aggregates)
            detected_ttps.extend(smtp_ttps)
        
        # Check for remote access TTPs
        if any(p in protocol_names for p in ['SSH', 'RDP', 'TELNET']):
            remote_ttps = self._analyze_remote_access(aggregates)
            detected_ttps.extend(remote_ttps)
        
        # Check for exfiltration indicators
        exfil_ttps = self._analyze_exfiltration(aggregates)
        detected_ttps.extend(exfil_ttps)
        
        # Check for beaconing behavior
        beacon_ttps = self._analyze_temporal_pattern(aggregates)
        detected_ttps.extend(beacon_ttps)
        
        # Deduplicate and sort by confidence
        seen_ids = set()
        unique_ttps = []
        for ttp in detected_ttps:
            if ttp.technique_id not in seen_ids:
                seen_ids.add(ttp.technique_id)
                unique_ttps.append(ttp)
        
        # Sort by confidence and return top 3-6
        unique_ttps.sort(key=lambda x: x.confidence, reverse=True)
        return unique_ttps[:6]
    
    def _analyze_dns(self, aggregates: Dict[str, Any]) -> List[ObservedTTP]:
        """Analyze DNS traffic for TTPs."""
        ttps = []
        dns_details = aggregates.get('protocol_details', {}).get('dns', {})
        
        if not dns_details:
            # Basic C2 via DNS if IOC is domain-related
            sightings = aggregates.get('sightings_by_log_type', {}).get('dns', 0)
            if sightings > 0:
                ttps.append(ObservedTTP(
                    technique_id='T1071.004',
                    technique_name='Application Layer Protocol: DNS',
                    justification=f'DNS queries observed to IOC-related domain ({sightings} sightings)',
                    confidence=0.6
                ))
            return ttps
        
        # Check for TXT queries (potential DNS tunneling)
        query_types = dns_details.get('query_types', {})
        if query_types.get('TXT', 0) > 5 or query_types.get('NULL', 0) > 0:
            ttps.append(ObservedTTP(
                technique_id='T1572',
                technique_name='Protocol Tunneling',
                justification=f'Unusual DNS query types observed (TXT: {query_types.get("TXT", 0)}, '
                             f'NULL: {query_types.get("NULL", 0)}) - potential DNS tunneling',
                confidence=0.75
            ))
        
        # High unique query count may indicate DGA
        unique_queries = dns_details.get('unique_queries', 0)
        if unique_queries > 50:
            ttps.append(ObservedTTP(
                technique_id='T1583.001',
                technique_name='Acquire Infrastructure: Domains',
                justification=f'High number of unique DNS queries ({unique_queries}) '
                             f'may indicate DGA or fast-flux behavior',
                confidence=0.65
            ))
        
        # NXDOMAIN responses
        response_codes = dns_details.get('response_codes', {})
        nxdomain = response_codes.get('NXDOMAIN', 0) + response_codes.get('3', 0)
        if nxdomain > 10:
            ttps.append(ObservedTTP(
                technique_id='T1071.004',
                technique_name='Application Layer Protocol: DNS',
                justification=f'Elevated NXDOMAIN responses ({nxdomain}) may indicate '
                             f'DGA probing or stale C2 infrastructure',
                confidence=0.55
            ))
        
        return ttps
    
    def _analyze_http_tls(self, aggregates: Dict[str, Any]) -> List[ObservedTTP]:
        """Analyze HTTP/TLS traffic for TTPs."""
        ttps = []
        http_details = aggregates.get('protocol_details', {}).get('http', {})
        tls_details = aggregates.get('protocol_details', {}).get('tls', {})
        
        # HTTP methods analysis
        if http_details:
            methods = http_details.get('methods', {})
            post_count = methods.get('POST', 0)
            get_count = methods.get('GET', 0)
            
            if post_count > 0:
                ttps.append(ObservedTTP(
                    technique_id='T1071.001',
                    technique_name='Application Layer Protocol: Web Protocols',
                    justification=f'HTTP traffic to IOC domain (POST: {post_count}, GET: {get_count}) '
                                 f'indicates potential C2 communication',
                    confidence=0.7
                ))
            
            # Multiple user agents may indicate evasion
            unique_uas = http_details.get('unique_user_agents', 0)
            if unique_uas > 5:
                ttps.append(ObservedTTP(
                    technique_id='T1071.001',
                    technique_name='Application Layer Protocol: Web Protocols',
                    justification=f'Multiple unique User-Agents ({unique_uas}) may indicate '
                                 f'user-agent rotation for evasion',
                    confidence=0.6
                ))
        
        # TLS analysis
        if tls_details:
            unique_ja3 = tls_details.get('unique_ja3', 0)
            versions = tls_details.get('versions', {})
            
            ttps.append(ObservedTTP(
                technique_id='T1573.002',
                technique_name='Encrypted Channel: Asymmetric Cryptography',
                justification=f'TLS-encrypted communications to IOC '
                             f'(JA3 fingerprints: {unique_ja3}, versions: {list(versions.keys())})',
                confidence=0.65
            ))
        
        return ttps
    
    def _analyze_smtp(self, aggregates: Dict[str, Any]) -> List[ObservedTTP]:
        """Analyze SMTP traffic for TTPs."""
        ttps = []
        smtp_details = aggregates.get('protocol_details', {}).get('smtp', {})
        
        sightings = aggregates.get('sightings_by_log_type', {}).get('smtp', 0)
        
        if sightings > 0:
            unique_senders = smtp_details.get('unique_senders', 0)
            unique_recipients = smtp_details.get('unique_recipients', 0)
            
            ttps.append(ObservedTTP(
                technique_id='T1566.002',
                technique_name='Phishing: Spearphishing Link',
                justification=f'SMTP traffic involving IOC ({sightings} messages, '
                             f'{unique_senders} senders, {unique_recipients} recipients) '
                             f'may indicate phishing activity',
                confidence=0.6
            ))
        
        return ttps
    
    def _analyze_remote_access(self, aggregates: Dict[str, Any]) -> List[ObservedTTP]:
        """Analyze remote access protocols for TTPs."""
        ttps = []
        log_types = aggregates.get('sightings_by_log_type', {})
        
        if log_types.get('ssh', 0) > 0:
            ttps.append(ObservedTTP(
                technique_id='T1021.004',
                technique_name='Remote Services: SSH',
                justification=f'SSH connections involving IOC ({log_types["ssh"]} sightings) '
                             f'may indicate remote access or lateral movement',
                confidence=0.6
            ))
        
        if log_types.get('rdp', 0) > 0:
            ttps.append(ObservedTTP(
                technique_id='T1021.001',
                technique_name='Remote Services: Remote Desktop Protocol',
                justification=f'RDP connections involving IOC ({log_types["rdp"]} sightings) '
                             f'may indicate remote access or lateral movement',
                confidence=0.65
            ))
        
        if log_types.get('telnet', 0) > 0:
            ttps.append(ObservedTTP(
                technique_id='T1021.004',
                technique_name='Remote Services: SSH',
                justification=f'Telnet connections ({log_types["telnet"]} sightings) '
                             f'to IOC indicate cleartext remote access attempt',
                confidence=0.7
            ))
        
        return ttps
    
    def _analyze_exfiltration(self, aggregates: Dict[str, Any]) -> List[ObservedTTP]:
        """Analyze traffic patterns for exfiltration indicators."""
        ttps = []
        
        # Check peer concentration
        peer_summary = aggregates.get('peer_entity_summary', {})
        top1_share = peer_summary.get('top1_share', 0)
        
        if top1_share > 0.8:
            ttps.append(ObservedTTP(
                technique_id='T1041',
                technique_name='Exfiltration Over C2 Channel',
                justification=f'High concentration of traffic to single peer ({top1_share:.0%}) '
                             f'may indicate data exfiltration over C2 channel',
                confidence=0.55
            ))
        
        # Multiple protocols to same IOC
        protocol_count = len(aggregates.get('protocol_coverage', []))
        if protocol_count >= 3:
            ttps.append(ObservedTTP(
                technique_id='T1071.001',
                technique_name='Application Layer Protocol: Web Protocols',
                justification=f'IOC accessed via {protocol_count} different protocols, '
                             f'indicating multi-channel communication',
                confidence=0.5
            ))
        
        return ttps
    
    def _analyze_temporal_pattern(self, aggregates: Dict[str, Any]) -> List[ObservedTTP]:
        """Analyze temporal distribution for beaconing patterns."""
        ttps = []
        
        temporal = aggregates.get('temporal_distribution', [])
        if not temporal or len(temporal) < 3:
            return ttps
        
        # Check for regular intervals (beaconing)
        counts = [t.get('count', 0) for t in temporal if t.get('count')]
        if counts:
            avg = sum(counts) / len(counts)
            variance = sum((c - avg) ** 2 for c in counts) / len(counts)
            
            # Low variance suggests regular beaconing
            if variance < avg * 0.5 and avg > 1:
                ttps.append(ObservedTTP(
                    technique_id='T1571',
                    technique_name='Non-Standard Port',
                    justification=f'Regular temporal pattern detected (avg: {avg:.1f}/bucket, '
                                 f'variance: {variance:.2f}) suggests potential beaconing behavior',
                    confidence=0.6
                ))
        
        return ttps


def map_ttps(aggregates: Dict[str, Any], 
             historical_stats: Optional[Dict[str, Any]] = None,
             config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Convenience function to map TTPs from aggregates.
    
    Args:
        aggregates: Aggregated Zeek log data
        historical_stats: Optional historical statistics
        config: Optional configuration
        
    Returns:
        List of TTP dictionaries for JSON output
    """
    mapper = NetworkTTPMapper(config)
    ttps = mapper.infer_ttps(aggregates, historical_stats)
    
    return [
        {
            'technique_id': ttp.technique_id,
            'technique_name': ttp.technique_name,
            'justification': ttp.justification,
            'confidence': round(ttp.confidence, 2)
        }
        for ttp in ttps
    ]
