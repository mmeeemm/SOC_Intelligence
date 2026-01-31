"""
Historical Statistics Computation

Computes and formats historical ticket statistics for an IOC.
"""

from typing import Any, Dict, Optional


def compute_historical_stats(raw_stats: Any) -> Dict[str, Any]:
    """
    Format historical statistics for report.
    
    Args:
        raw_stats: HistoricalStats from PostgreSQL connector
        
    Returns:
        Dictionary ready for JSON output
    """
    if hasattr(raw_stats, '__dict__'):
        total = raw_stats.total_tickets
        tp = raw_stats.threat_count
        fp = raw_stats.false_positive_count
        ratio = raw_stats.threat_ratio
        last_observed = raw_stats.last_observed_ticket
    else:
        total = raw_stats.get('total_tickets', 0)
        tp = raw_stats.get('threat_count', 0)
        fp = raw_stats.get('false_positive_count', 0)
        ratio = raw_stats.get('threat_ratio')
        last_observed = raw_stats.get('last_observed_ticket')
    
    return {
        'total_tickets': total,
        'threat_count': tp,
        'false_positive_count': fp,
        'threat_ratio': round(ratio, 4) if ratio is not None else None,
        'last_observed_ticket': last_observed.isoformat() if last_observed else None
    }
