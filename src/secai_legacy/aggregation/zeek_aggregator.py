"""
Zeek Log Aggregator

Transforms raw Zeek aggregate data into report-ready format.
"""

from datetime import datetime
from typing import Any, Dict, Optional


def aggregate_zeek_data(raw_aggregates: Any) -> Dict[str, Any]:
    """
    Transform Zeek aggregates into report format.
    
    Args:
        raw_aggregates: ZeekAggregates from Impala connector
        
    Returns:
        Dictionary ready for JSON output
    """
    # Handle both dict and dataclass inputs
    if hasattr(raw_aggregates, '__dict__'):
        data = {
            'total_sightings': raw_aggregates.total_sightings,
            'distinct_src_ips': list(raw_aggregates.distinct_src_ips),
            'distinct_dst_ips': list(raw_aggregates.distinct_dst_ips),
            'protocol_coverage': raw_aggregates.protocol_coverage,
            'country_pairs': raw_aggregates.country_pairs,
            'temporal_buckets': raw_aggregates.temporal_buckets,
            'fields_present': raw_aggregates.fields_present,
            'fields_used': raw_aggregates.fields_used,
            'sightings_by_log_type': raw_aggregates.sightings_by_log_type,
            'sightings_by_field': raw_aggregates.sightings_by_field,
            'first_seen': raw_aggregates.first_seen,
            'last_seen': raw_aggregates.last_seen,
            'protocol_details': raw_aggregates.protocol_details,
            'peer_entities': raw_aggregates.peer_entities
        }
    else:
        data = dict(raw_aggregates)
    
    # Build current window summary
    current_summary = {
        'total_ioc_sightings': data.get('total_sightings', 0),
        'distinct_src_ip_count': len(data.get('distinct_src_ips', [])),
        'distinct_dst_ip_count': len(data.get('distinct_dst_ips', [])),
        'distinct_country_pairs': len(data.get('country_pairs', {})),
        'protocol_coverage': data.get('protocol_coverage', []),
        'sightings_by_log_type': data.get('sightings_by_log_type', {}),
        'sightings_by_matched_field': data.get('sightings_by_field', {}),
        'country_pair_distribution': _format_country_pairs(data.get('country_pairs', {})),
        'peer_entity_summary': _format_peer_summary(data.get('peer_entities', [])),
        'temporal_distribution': _format_temporal(data.get('temporal_buckets', {})),
        'protocol_specific_details': data.get('protocol_details', {})
    }
    
    # Build field review
    field_review = {
        'fields_present': data.get('fields_present', {}),
        'fields_used_in_summary': data.get('fields_used', {})
    }
    
    # Build additional assets
    all_ips = set(data.get('distinct_src_ips', [])) | set(data.get('distinct_dst_ips', []))
    additional_assets = {
        'distinct_ip_total': len(all_ips),
        'distinct_ip_excluding_trigger': max(0, len(all_ips) - 1),
        'nat_aggregation_note': 'IP addresses observed at network edge may represent NAT-aggregated traffic from multiple internal hosts.'
    }
    
    return {
        'current_window_summary': current_summary,
        'zeek_field_review': field_review,
        'additional_assets_involved': additional_assets,
        'first_seen': data.get('first_seen').isoformat() if data.get('first_seen') else None,
        'last_seen': data.get('last_seen').isoformat() if data.get('last_seen') else None
    }


def _format_country_pairs(pairs: Dict[tuple, int]) -> list:
    """Format country pairs for JSON output."""
    result = []
    for (src, dst), count in pairs.items():
        result.append({
            'src_country': src,
            'dst_country': dst,
            'count': count
        })
    return sorted(result, key=lambda x: x['count'], reverse=True)[:20]


def _format_peer_summary(peers: list) -> Dict[str, Any]:
    """Format peer entity summary."""
    top_peers = []
    top1_share = 0.0
    top3_share = 0.0
    
    for item in peers:
        if 'ip' in item:
            top_peers.append(item)
        elif 'top1_share' in item:
            top1_share = item['top1_share']
        elif 'top3_share' in item:
            top3_share = item['top3_share']
    
    return {
        'top_peers': top_peers[:10],
        'top1_share': top1_share,
        'top3_share': top3_share
    }


def _format_temporal(buckets: Dict[str, int]) -> list:
    """Format temporal distribution."""
    result = []
    for bucket_key, count in sorted(buckets.items()):
        result.append({
            'bucket_start': bucket_key,
            'bucket_end': bucket_key,  # Simplified
            'count': count
        })
    return result
