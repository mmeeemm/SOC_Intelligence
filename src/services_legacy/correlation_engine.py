"""
TOON Correlation Engine
Multi-level correlation with deterministic degradation (packet → transaction → flow).
"""

import logging
import hashlib
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from collections import defaultdict

from src.utils.toon_format import parse_toon_block

logger = logging.getLogger(__name__)


@dataclass
class CorrGroup:
    """Represents a correlated group of TOON blocks."""
    corr_id: str
    corr_level: str  # packet|transaction|flow
    corr_key: str  # exact keys used for correlation
    corr_confidence: str  # high|medium|low
    blocks: List[str]  # TOON blocks in stable order
    
    def to_toon(self) -> str:
        """Convert CorrGroup to TOON format."""
        from src.utils.toon_format import build_corr_group
        return build_corr_group(
            self.corr_id,
            self.corr_level,
            self.corr_key,
            self.corr_confidence,
            self.blocks
        )


class CorrelationEngine:
    """
    Multi-level correlation engine with deterministic degradation.
    
    Correlation priority (highest to lowest):
    A) Packet-level: frame.number or pcap_packet_id
    B) Packet-level derived: ts_precise + 5-tuple + ip_id + tcp_seq
    C) Transaction-level: DNS txid, HTTP stream_id, etc.
    D) Flow-level: Zeek uid or 5-tuple + ts_bucket
    """
    
    def __init__(self, ts_bucket_seconds: int = 1):
        """
        Args:
            ts_bucket_seconds: Time bucket for flow-level correlation (default: 1s)
        """
        self.ts_bucket_seconds = ts_bucket_seconds
        self.stats = {
            'packet_level': 0,
            'packet_derived': 0,
            'transaction_level': 0,
            'flow_level': 0,
            'uncorrelated': 0
        }
    
    def correlate(self, toon_blocks_list: List[str]) -> List[CorrGroup]:
        """
        Correlate TOON blocks into CORR_GROUPs.
        
        Args:
            toon_blocks_list: List of TOON block strings (each may contain multiple blocks)
        
        Returns:
            List of CorrGroup objects
        """
        # Parse all blocks
        parsed_blocks = []
        for toon_str in toon_blocks_list:
            blocks = self._parse_multi_block(toon_str)
            parsed_blocks.append(blocks)
        
        # Group by correlation key
        correlation_groups = defaultdict(list)
        
        for blocks in parsed_blocks:
            # Extract metadata for correlation
            meta = self._extract_correlation_metadata(blocks)
            
            # Try correlation methods in priority order
            corr_result = self._try_correlate(meta, blocks)
            
            if corr_result:
                corr_key, corr_level, corr_confidence = corr_result
                correlation_groups[corr_key].append({
                    'blocks': blocks,
                    'level': corr_level,
                    'confidence': corr_confidence,
                    'meta': meta
                })
            else:
                self.stats['uncorrelated'] += 1
                logger.warning(f"Could not correlate blocks: {meta}")
        
        # Build CorrGroup objects
        corr_groups = []
        for corr_key, entries in correlation_groups.items():
            # Merge blocks from same correlation key
            merged_blocks = self._merge_and_deduplicate(entries)
            
            # Use first entry's level and confidence (should all be same)
            corr_level = entries[0]['level']
            corr_confidence = entries[0]['confidence']
            
            # Generate deterministic corr_id
            corr_id = self._generate_corr_id(corr_key, corr_level)
            
            corr_group = CorrGroup(
                corr_id=corr_id,
                corr_level=corr_level,
                corr_key=corr_key,
                corr_confidence=corr_confidence,
                blocks=merged_blocks
            )
            
            corr_groups.append(corr_group)
        
        return corr_groups
    
    def _parse_multi_block(self, toon_str: str) -> List[Dict[str, Any]]:
        """Parse a multi-block TOON string into list of block dicts."""
        blocks = []
        current_block_lines = []
        
        for line in toon_str.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Start of new block
            if line.startswith('[') and line.endswith(']'):
                # Save previous block if exists
                if current_block_lines:
                    block_text = '\n'.join(current_block_lines)
                    parsed = parse_toon_block(block_text)
                    if parsed:
                        blocks.append(parsed)
                    current_block_lines = []
                
                current_block_lines.append(line)
            else:
                current_block_lines.append(line)
        
        # Save last block
        if current_block_lines:
            block_text = '\n'.join(current_block_lines)
            parsed = parse_toon_block(block_text)
            if parsed:
                blocks.append(parsed)
        
        return blocks
    
    def _extract_correlation_metadata(self, blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract all fields needed for correlation attempts."""
        meta = {}
        
        for block in blocks:
            block_type = block.get('_type', '')
            
            # META block
            if block_type == 'META':
                meta['ts'] = block.get('ts')
                meta['ts_precise'] = block.get('ts_precise')
                meta['frame_number'] = block.get('frame_number')
                meta['pcap_packet_id'] = block.get('pcap_packet_id')
                meta['zeek_uid'] = block.get('zeek_uid')
                meta['community_id'] = block.get('community_id')
            
            # FLOW block
            elif block_type == 'FLOW':
                meta['src_ip'] = block.get('src_ip')
                meta['dst_ip'] = block.get('dst_ip')
                meta['src_port'] = block.get('src_port')
                meta['dst_port'] = block.get('dst_port')
                meta['proto'] = block.get('proto')
            
            # Protocol-specific transaction IDs
            elif block_type.startswith('PROTO:'):
                proto = block_type.split(':')[1]
                if proto == 'DNS':
                    meta['dns_id'] = block.get('id') or block.get('txid')
                elif proto == 'HTTP':
                    meta['http_stream_id'] = block.get('stream_id')
                elif proto == 'TLS':
                    meta['tls_handshake_id'] = block.get('handshake_id')
                elif proto == 'IP':
                    meta['ip_id'] = block.get('id')
                elif proto == 'TCP':
                    meta['tcp_seq'] = block.get('seq')
        
        return meta
    
    def _try_correlate(self, meta: Dict[str, Any], blocks: List[Dict[str, Any]]) -> Optional[tuple]:
        """
        Try correlation methods in priority order.
        
        Returns:
            (corr_key, corr_level, corr_confidence) or None
        """
        # A) Packet-level (frame.number or pcap_packet_id)
        if meta.get('frame_number'):
            self.stats['packet_level'] += 1
            return (f"frame.number={meta['frame_number']}", 'packet', 'high')
        if meta.get('pcap_packet_id'):
            self.stats['packet_level'] += 1
            return (f"pcap_packet_id={meta['pcap_packet_id']}", 'packet', 'high')
        
        # B) Packet-level derived (ts_precise + 5-tuple + ip_id + tcp_seq)
        has_5tuple = all(meta.get(k) for k in ['src_ip', 'dst_ip', 'proto'])
        has_ports = meta.get('src_port') and meta.get('dst_port')
        
        if meta.get('ts_precise') and has_5tuple and meta.get('ip_id') and meta.get('tcp_seq'):
            self.stats['packet_derived'] += 1
            key = f"ts={meta['ts_precise']},5tuple={meta['src_ip']}:{meta.get('src_port', 'X')}->{meta['dst_ip']}:{meta.get('dst_port', 'X')}/{meta['proto']},ip_id={meta['ip_id']},tcp_seq={meta['tcp_seq']}"
            return (key, 'packet', 'medium')
        
        # C) Transaction-level (DNS txid, HTTP stream_id, etc.)
        if meta.get('dns_id') and has_5tuple:
            self.stats['transaction_level'] += 1
            key = f"dns_id={meta['dns_id']},5tuple={meta['src_ip']}:{meta.get('src_port', 'X')}->{meta['dst_ip']}:{meta.get('dst_port', 'X')}"
            return (key, 'transaction', 'medium')
        
        if meta.get('http_stream_id') and has_5tuple:
            self.stats['transaction_level'] += 1
            key = f"http_stream={meta['http_stream_id']},5tuple={meta['src_ip']}:{meta.get('src_port', 'X')}->{meta['dst_ip']}:{meta.get('dst_port', 'X')}"
            return (key, 'transaction', 'medium')
        
        if meta.get('tls_handshake_id') and has_5tuple:
            self.stats['transaction_level'] += 1
            key = f"tls_handshake={meta['tls_handshake_id']},5tuple={meta['src_ip']}:{meta.get('src_port', 'X')}->{meta['dst_ip']}:{meta.get('dst_port', 'X')}"
            return (key, 'transaction', 'medium')
        
        # If transaction ID exists but 5-tuple incomplete, lower confidence
        if meta.get('dns_id'):
            self.stats['transaction_level'] += 1
            return (f"dns_id={meta['dns_id']}", 'transaction', 'low')
        
        # D) Flow-level (Zeek uid or 5-tuple + ts_bucket)
        if meta.get('zeek_uid'):
            self.stats['flow_level'] += 1
            return (f"zeek_uid={meta['zeek_uid']}", 'flow', 'medium')
        
        if has_5tuple and meta.get('ts'):
            # Bucket timestamp
            ts_bucket = self._bucket_timestamp(meta['ts'])
            if ts_bucket:
                self.stats['flow_level'] += 1
                key = f"5tuple={meta['src_ip']}:{meta.get('src_port', 'X')}->{meta['dst_ip']}:{meta.get('dst_port', 'X')}/{meta['proto']},ts_bucket={ts_bucket}"
                return (key, 'flow', 'low')
        
        # Flow-level with only 5-tuple (no timestamp)
        if has_5tuple:
            self.stats['flow_level'] += 1
            key = f"5tuple={meta['src_ip']}:{meta.get('src_port', 'X')}->{meta['dst_ip']}:{meta.get('dst_port', 'X')}/{meta['proto']}"
            return (key, 'flow', 'low')
        
        # Cannot correlate
        return None
    
    def _bucket_timestamp(self, ts_str: str) -> Optional[str]:
        """Bucket timestamp to nearest ts_bucket_seconds."""
        try:
            from datetime import datetime
            # Try parsing ISO format
            if 'T' in ts_str:
                dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            else:
                # Unix timestamp
                dt = datetime.fromtimestamp(float(ts_str))
            
            # Bucket to nearest second/minute
            bucket = int(dt.timestamp() // self.ts_bucket_seconds) * self.ts_bucket_seconds
            return str(bucket)
        except Exception as e:
            logger.debug(f"Could not bucket timestamp {ts_str}: {e}")
            return None
    
    def _generate_corr_id(self, corr_key: str, corr_level: str) -> str:
        """Generate deterministic correlation ID from key."""
        # Use hash for shorter IDs
        key_hash = hashlib.md5(corr_key.encode()).hexdigest()[:8]
        return f"{corr_level}_{key_hash}"
    
    def _merge_and_deduplicate(self, entries: List[Dict[str, Any]]) -> List[str]:
        """
        Merge blocks from multiple entries and deduplicate.
        Returns blocks in stable order: META, FLOW, IP/IPV6, TCP/UDP/ICMP, others, IDS.
        """
        # Collect all blocks by type
        blocks_by_type = defaultdict(list)
        
        for entry in entries:
            for block in entry['blocks']:
                block_type = block.get('_type', '')
                blocks_by_type[block_type].append(block)
        
        # Deduplicate and merge
        merged_blocks = []
        
        # Stable ordering
        order = [
            'META',
            'FLOW',
            'PROTO:IP', 'PROTO:IPV6',
            'PROTO:TCP', 'PROTO:UDP', 'PROTO:ICMP',
            # Other protocols will be added alphabetically
            'PROTO:IDS'
        ]
        
        # Add META
        if 'META' in blocks_by_type:
            merged_meta = self._merge_blocks(blocks_by_type['META'])
            merged_blocks.append(self._dict_to_toon_block(merged_meta))
        
        # Add FLOW
        if 'FLOW' in blocks_by_type:
            merged_flow = self._merge_blocks(blocks_by_type['FLOW'])
            merged_blocks.append(self._dict_to_toon_block(merged_flow))
        
        # Add protocol blocks in order
        protocol_blocks = {k: v for k, v in blocks_by_type.items() if k.startswith('PROTO:')}
        
        # First add ordered protocols
        for proto in order:
            if proto in protocol_blocks:
                merged_proto = self._merge_blocks(protocol_blocks[proto])
                merged_blocks.append(self._dict_to_toon_block(merged_proto))
                del protocol_blocks[proto]
        
        # Then add remaining protocols alphabetically
        for proto in sorted(protocol_blocks.keys()):
            if proto != 'PROTO:IDS':  # IDS goes last
                merged_proto = self._merge_blocks(protocol_blocks[proto])
                merged_blocks.append(self._dict_to_toon_block(merged_proto))
        
        # Add IDS last
        if 'PROTO:IDS' in blocks_by_type:
            merged_ids = self._merge_blocks(blocks_by_type['PROTO:IDS'])
            merged_blocks.append(self._dict_to_toon_block(merged_ids))
        
        return merged_blocks
    
    def _merge_blocks(self, blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple blocks of same type, preferring most specific values."""
        merged = {'_type': blocks[0].get('_type', '')}
        
        for block in blocks:
            for key, value in block.items():
                if key == '_type':
                    continue
                
                # If key doesn't exist, add it
                if key not in merged:
                    merged[key] = value
                else:
                    # Prefer non-empty, more specific values
                    existing = merged[key]
                    if value and (not existing or len(str(value)) > len(str(existing))):
                        merged[key] = value
        
        return merged
    
    def _dict_to_toon_block(self, block_dict: Dict[str, Any]) -> str:
        """Convert block dictionary back to TOON format."""
        lines = [f"[{block_dict['_type']}]"]
        for key, value in sorted(block_dict.items()):
            if key != '_type':
                lines.append(f"{key}={value}")
        return '\n'.join(lines)
    
    def get_stats(self) -> Dict[str, int]:
        """Get correlation statistics."""
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset statistics."""
        self.stats = {
            'packet_level': 0,
            'packet_derived': 0,
            'transaction_level': 0,
            'flow_level': 0,
            'uncorrelated': 0
        }


# Global singleton
correlation_engine = CorrelationEngine()
