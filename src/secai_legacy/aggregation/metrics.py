"""
Metrics Computation Utilities

Additional metrics computations for peer analysis and temporal patterns.
"""

from typing import Any, Dict, List


def compute_peer_metrics(ips: List[str], counts: Dict[str, int]) -> Dict[str, Any]:
    """
    Compute peer concentration metrics.
    
    Args:
        ips: List of IP addresses
        counts: Dict of IP to count
        
    Returns:
        Peer metrics including concentration ratios
    """
    if not counts:
        return {
            'top_peers': [],
            'top1_share': 0.0,
            'top3_share': 0.0,
            'concentration_level': 'none'
        }
    
    sorted_peers = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    total = sum(counts.values())
    
    top_peers = [{'ip': ip, 'count': cnt} for ip, cnt in sorted_peers[:10]]
    
    top1 = sorted_peers[0][1] / total if total > 0 and len(sorted_peers) >= 1 else 0
    top3 = sum(p[1] for p in sorted_peers[:3]) / total if total > 0 else 0
    
    # Determine concentration level
    if top1 > 0.7:
        concentration = 'high'
    elif top1 > 0.5:
        concentration = 'medium'
    else:
        concentration = 'low'
    
    return {
        'top_peers': top_peers,
        'top1_share': round(top1, 4),
        'top3_share': round(top3, 4),
        'concentration_level': concentration
    }


def compute_temporal_metrics(buckets: Dict[str, int]) -> Dict[str, Any]:
    """
    Compute temporal distribution metrics.
    
    Args:
        buckets: Dict of time bucket to count
        
    Returns:
        Temporal metrics including beaconing indicators
    """
    if not buckets:
        return {
            'bucket_count': 0,
            'active_buckets': 0,
            'avg_per_bucket': 0.0,
            'variance': 0.0,
            'beaconing_indicator': 'none'
        }
    
    counts = list(buckets.values())
    total_buckets = len(buckets)
    active_buckets = sum(1 for c in counts if c > 0)
    avg = sum(counts) / total_buckets
    variance = sum((c - avg) ** 2 for c in counts) / total_buckets
    
    # Detect beaconing patterns
    if variance < avg * 0.3 and avg > 1:
        beaconing = 'strong'
    elif variance < avg * 0.7 and avg > 0.5:
        beaconing = 'moderate'
    else:
        beaconing = 'none'
    
    return {
        'bucket_count': total_buckets,
        'active_buckets': active_buckets,
        'avg_per_bucket': round(avg, 2),
        'variance': round(variance, 2),
        'beaconing_indicator': beaconing
    }
