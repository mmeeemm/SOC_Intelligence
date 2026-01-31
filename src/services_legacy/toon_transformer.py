"""
TOON Transformer Service
Converts raw telemetry from multiple sources (T Shark, Zeek, Snort, DuckDB) into TOON format.
"""

import logging
from typing import Dict, Any, List, Optional
import pandas as pd
from datetime import datetime

from src.utils.toon_format import (
    build_proto_block,
    build_meta_block,
    build_flow_block,
    apply_hygiene,
    enforce_layer_policy,
    normalize_protocol_name
)

logger = logging.getLogger(__name__)


class TOONTransformer:
    """
    Multi-source TOON transformation engine.
    Converts raw telemetry into deterministic, validated TOON blocks.
    """
    
    def __init__(self):
        self.stats = {
            'transformed': 0,
            'skipped_empty': 0,
            'skipped_l1l2': 0
        }
    
    def from_tshark(self, packet: Dict[str, Any]) -> Optional[str]:
        """
        Transform TShark/PyShark packet dict into TOON blocks.
        
        Args:
            packet: Dictionary from TShark JSON or PyShark packet
        
        Returns:
            TOON blocks as string, or None if no valid L3+ data
        """
        blocks = []
        
        # Apply layer policy first
        packet = enforce_layer_policy(packet)
        if not packet:
            self.stats['skipped_l1l2'] += 1
            return None
        
        # Build META block (timing info)
        meta_facts = {}
        if '@timestamp' in packet:
            meta_facts['ts'] = packet['@timestamp']
        if 'frame.time_epoch' in packet:
            meta_facts['ts_precise'] = packet['frame.time_epoch']
        if 'frame.number' in packet:
            meta_facts['frame_number'] = packet['frame.number']
        
        meta_block = build_meta_block(**meta_facts)
        if meta_block:
            blocks.append(meta_block)
        
        # Build FLOW block (5-tuple)
        flow_facts = {}
        if 'source.ip' in packet or 'ip.src' in packet:
            flow_facts['src_ip'] = packet.get('source.ip') or packet.get('ip.src')
        if 'destination.ip' in packet or 'ip.dst' in packet:
            flow_facts['dst_ip'] = packet.get('destination.ip') or packet.get('ip.dst')
        if 'source.port' in packet or 'tcp.srcport' in packet or 'udp.srcport' in packet:
            flow_facts['src_port'] = (
                packet.get('source.port') or 
                packet.get('tcp.srcport') or 
                packet.get('udp.srcport')
            )
        if 'destination.port' in packet or 'tcp.dstport' in packet or 'udp.dstport' in packet:
            flow_facts['dst_port'] = (
                packet.get('destination.port') or 
                packet.get('tcp.dstport') or 
                packet.get('udp.dstport')
            )
        if 'network.transport' in packet or 'ip.proto' in packet:
            flow_facts['proto'] = packet.get('network.transport') or packet.get('ip.proto')
        
        flow_block = build_flow_block(**flow_facts)
        if flow_block:
            blocks.append(flow_block)
        
        # Build protocol blocks (IP, TCP, DNS, TLS, HTTP, etc.)
        protocols_emitted = set()
        
        # IP layer
        ip_facts = {}
        for key in ['ip.id', 'ip.ttl', 'ip.len', 'ip.flags', 'ipv6.flow']:
            if key in packet and apply_hygiene(packet[key]):
                ip_facts[key.replace('ip.', '')] = packet[key]
        if ip_facts:
            proto = 'IPV6' if 'ipv6.flow' in packet else 'IP'
            ip_block = build_proto_block(proto, ip_facts)
            if ip_block:
                blocks.append(ip_block)
                protocols_emitted.add(proto)
        
        # TCP layer
        tcp_facts = {}
        for key in ['tcp.seq', 'tcp.ack', 'tcp.flags', 'tcp.window_size', 
                    'tcp.analysis.initial_rtt', 'tcp.analysis.retransmission']:
            if key in packet and apply_hygiene(packet[key]):
                tcp_facts[key.replace('tcp.', '')] = packet[key]
        if tcp_facts or packet.get('network.transport') == 'tcp':
            tcp_block = build_proto_block('TCP', tcp_facts)
            if tcp_block:
                blocks.append(tcp_block)
                protocols_emitted.add('TCP')
        
        # UDP layer
        udp_facts = {}
        for key in ['udp.length', 'udp.checksum']:
            if key in packet and apply_hygiene(packet[key]):
                udp_facts[key.replace('udp.', '')] = packet[key]
        if udp_facts or packet.get('network.transport') == 'udp':
            udp_block = build_proto_block('UDP', udp_facts)
            if udp_block:
                blocks.append(udp_block)
                protocols_emitted.add('UDP')
        
        # DNS layer
        dns_facts = {}
        for key in ['dns.question.name', 'dns.qry.type', 'dns.flags.response', 
                    'dns.id', 'dns.answers']:
            if key in packet and apply_hygiene(packet[key]):
                dns_facts[key.replace('dns.', '')] = packet[key]
        if dns_facts:
            dns_block = build_proto_block('DNS', dns_facts)
            if dns_block:
                blocks.append(dns_block)
                protocols_emitted.add('DNS')
        
        # TLS layer
        tls_facts = {}
        for key in ['tls.handshake.ja3', 'tls.client.server_name', 'tls.handshake.version',
                    'tls.handshake.ciphersuite']:
            if key in packet and apply_hygiene(packet[key]):
                tls_facts[key.replace('tls.', '')] = packet[key]
        if tls_facts:
            tls_block = build_proto_block('TLS', tls_facts)
            if tls_block:
                blocks.append(tls_block)
                protocols_emitted.add('TLS')
        
        # HTTP layer
        http_facts = {}
        for key in ['http.request.method', 'http.response.code', 'http.host',
                    'http.user_agent', 'http.request.uri']:
            if key in packet and apply_hygiene(packet[key]):
                http_facts[key.replace('http.', '')] = packet[key]
        if http_facts:
            http_block = build_proto_block('HTTP', http_facts)
            if http_block:
                blocks.append(http_block)
                protocols_emitted.add('HTTP')
        
        if not blocks:
            self.stats['skipped_empty'] += 1
            return None
        
        self.stats['transformed'] += 1
        return "\n".join(blocks)
    
    def from_zeek(self, conn_log: Dict[str, Any]) -> Optional[str]:
        """
        Transform Zeek conn.log entry into TOON blocks.
        
        Args:
            conn_log: Dictionary from Zeek conn.log
        
        Returns:
            TOON blocks as string, or None if no valid data
        """
        blocks = []
        
        # Build META block
        meta_facts = {}
        if 'ts' in conn_log:
            meta_facts['ts'] = conn_log['ts']
        if 'uid' in conn_log:
            meta_facts['zeek_uid'] = conn_log['uid']
        
        meta_block = build_meta_block(**meta_facts)
        if meta_block:
            blocks.append(meta_block)
        
        # Build FLOW block
        flow_block = build_flow_block(
            src_ip=conn_log.get('id.orig_h'),
            dst_ip=conn_log.get('id.resp_h'),
            src_port=conn_log.get('id.orig_p'),
            dst_port=conn_log.get('id.resp_p'),
            proto=conn_log.get('proto'),
            duration=conn_log.get('duration'),
            orig_bytes=conn_log.get('orig_bytes'),
            resp_bytes=conn_log.get('resp_bytes')
        )
        if flow_block:
            blocks.append(flow_block)
        
        # Build protocol-specific blocks
        service = conn_log.get('service')
        if service and apply_hygiene(service):
            proto_facts = {
                'service': service,
                'conn_state': conn_log.get('conn_state'),
                'orig_pkts': conn_log.get('orig_pkts'),
                'resp_pkts': conn_log.get('resp_pkts')
            }
            # Filter None values
            proto_facts = {k: v for k, v in proto_facts.items() if apply_hygiene(v)}
            
            proto_block = build_proto_block(service, proto_facts)
            if proto_block:
                blocks.append(proto_block)
        
        if not blocks:
            self.stats['skipped_empty'] += 1
            return None
        
        self.stats['transformed'] += 1
        return "\n".join(blocks)
    
    def from_snort(self, alert: Dict[str, Any]) -> Optional[str]:
        """
        Transform Snort alert into TOON blocks (as [PROTO:IDS]).
        
        Args:
            alert: Dictionary from Snort alert
        
        Returns:
            TOON blocks as string
        """
        blocks = []
        
        # Build META block
        meta_facts = {}
        if '@timestamp' in alert:
            meta_facts['ts'] = alert['@timestamp']
        if 'alert_id' in alert:
            meta_facts['alert_id'] = alert['alert_id']
        
        meta_block = build_meta_block(**meta_facts)
        if meta_block:
            blocks.append(meta_block)
        
        # Build FLOW block if available
        if any(k in alert for k in ['source.ip', 'destination.ip']):
            flow_block = build_flow_block(
                src_ip=alert.get('source.ip'),
                dst_ip=alert.get('destination.ip'),
                src_port=alert.get('source.port'),
                dst_port=alert.get('destination.port'),
                proto=alert.get('network.transport')
            )
            if flow_block:
                blocks.append(flow_block)
        
        # Build IDS block
        ids_facts = {
            'alert_id': alert.get('alert_id'),
            'alert_message': alert.get('alert.message'),
            'signature_id': alert.get('alert.signature_id'),
            'severity': alert.get('alert.severity'),
            'risk_score': alert.get('risk_score')
        }
        ids_facts = {k: v for k, v in ids_facts.items() if apply_hygiene(v)}
        
        if ids_facts:
            ids_block = build_proto_block('IDS', ids_facts)
            if ids_block:
                blocks.append(ids_block)
        
        if not blocks:
            self.stats['skipped_empty'] += 1
            return None
        
        self.stats['transformed'] += 1
        return "\n".join(blocks)
    
    def from_duckdb(self, row: pd.Series) -> Optional[str]:
        """
        Transform DuckDB purified_events row into TOON blocks.
        
        Args:
            row: pandas Series from purified_events query
        
        Returns:
            TOON blocks as string
        """
        # Convert Series to dict
        record = row.to_dict()
        
        blocks = []
        
        # Build META block
        meta_facts = {}
        if '@timestamp' in record:
            meta_facts['ts'] = record['@timestamp']
        if 'network.community_id' in record:
            meta_facts['community_id'] = record['network.community_id']
        
        meta_block = build_meta_block(**meta_facts)
        if meta_block:
            blocks.append(meta_block)
        
        # Build FLOW block
        flow_block = build_flow_block(
            src_ip=record.get('source.ip'),
            dst_ip=record.get('destination.ip'),
            src_port=record.get('source.port'),
            dst_port=record.get('destination.port'),
            proto=record.get('network.transport'),
            bytes=record.get('network.bytes')
        )
        if flow_block:
            blocks.append(flow_block)
        
        # Build protocol block based on network.protocol
        protocol = record.get('network.protocol')
        if protocol and apply_hygiene(protocol):
            proto_facts = {
                'protocol': protocol,
                'risk_score': record.get('risk_score'),
                'osi_stack': record.get('osi_stack')
            }
            
            # Add protocol-specific fields
            if 'dns.question.name' in record and apply_hygiene(record.get('dns.question.name')):
                proto_facts['dns_query'] = record['dns.question.name']
            if 'tls.client.server_name' in record and apply_hygiene(record.get('tls.client.server_name')):
                proto_facts['tls_sni'] = record['tls.client.server_name']
            if 'tls.handshake.ja3' in record and apply_hygiene(record.get('tls.handshake.ja3')):
                proto_facts['ja3'] = record['tls.handshake.ja3']
            
            proto_facts = {k: v for k, v in proto_facts.items() if apply_hygiene(v)}
            
            proto_block = build_proto_block(protocol, proto_facts)
            if proto_block:
                blocks.append(proto_block)
        
        # Add IDS block if alert exists
        if record.get('alert_id') and apply_hygiene(record.get('alert_id')):
            ids_facts = {
                'alert_id': record.get('alert_id'),
                'mitre_attack': record.get('mitre_attack')
            }
            ids_facts = {k: v for k, v in ids_facts.items() if apply_hygiene(v)}
            
            ids_block = build_proto_block('IDS', ids_facts)
            if ids_block:
                blocks.append(ids_block)
        
        if not blocks:
            self.stats['skipped_empty'] += 1
            return None
        
        self.stats['transformed'] += 1
        return "\n".join(blocks)
    
    def batch_transform(self, records: List[Dict[str, Any]], source: str) -> List[str]:
        """
        Transform multiple records from a specific source.
        
        Args:
            records: List of record dictionaries
            source: 'tshark' | 'zeek' | 'snort' | 'duckdb'
        
        Returns:
            List of TOON block strings (excluding None entries)
        """
        transformer_map = {
            'tshark': self.from_tshark,
            'zeek': self.from_zeek,
            'snort': self.from_snort,
            'duckdb': lambda r: self.from_duckdb(pd.Series(r)) if isinstance(r, dict) else self.from_duckdb(r)
        }
        
        if source not in transformer_map:
            logger.error(f"Unknown source: {source}")
            return []
        
        transformer = transformer_map[source]
        results = []
        
        for record in records:
            try:
                toon_blocks = transformer(record)
                if toon_blocks:
                    results.append(toon_blocks)
            except Exception as e:
                logger.error(f"Transformation error for {source}: {e}")
                continue
        
        return results
    
    def get_stats(self) -> Dict[str, int]:
        """Get transformation statistics."""
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset statistics counters."""
        self.stats = {'transformed': 0, 'skipped_empty': 0, 'skipped_l1l2': 0}


# Global singleton
toon_transformer = TOONTransformer()
