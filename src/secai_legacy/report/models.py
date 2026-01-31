"""
Pydantic Models for Report Data

Defines structured data models for report generation.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TriggerInfo(BaseModel):
    """Trigger information for the ticket."""
    type: str = Field(..., description="ioc_match, ids_signature, or ids_hash")
    value: str
    timestamp: datetime


class TicketInfo(BaseModel):
    """Ticket metadata."""
    id: str
    created_at: datetime
    status: str = "open"
    severity: str = "medium"
    outcome: str = "Unset"
    trigger: TriggerInfo
    data_sources: List[str] = Field(default_factory=list)


class AnalysisWindow(BaseModel):
    """Time window for analysis."""
    anchor_t0: datetime
    start: datetime
    end: datetime
    duration_hours: float = 48.0


class IndicatorInfo(BaseModel):
    """IOC indicator information."""
    ioc_type: str
    ioc_value: str
    matched_fields: List[str] = Field(default_factory=list)
    protocols_involved: List[str] = Field(default_factory=list)
    first_seen_in_window: Optional[datetime] = None
    last_seen_in_window: Optional[datetime] = None


class AnalysisWeighting(BaseModel):
    """Weighting for analysis."""
    current_behavior: float = 0.75
    historical_outcomes: float = 0.25


class HistoricalStats(BaseModel):
    """Historical ticket statistics."""
    total_tickets: int = 0
    threat_count: int = 0
    false_positive_count: int = 0
    threat_ratio: Optional[float] = None
    last_observed_ticket: Optional[datetime] = None


class ProtocolCoverage(BaseModel):
    """Protocol coverage entry."""
    protocol: str
    zeek_log_type: str
    sightings: int
    distinct_src_ip: int = 0
    distinct_dst_ip: int = 0
    matched_fields_used: List[str] = Field(default_factory=list)


class CountryPair(BaseModel):
    """Country pair distribution entry."""
    src_country: str
    dst_country: str
    count: int


class PeerEntity(BaseModel):
    """Peer entity entry."""
    ip: str
    count: int
    country: str = "Unknown"


class PeerSummary(BaseModel):
    """Peer entity summary."""
    top_peers: List[PeerEntity] = Field(default_factory=list)
    top1_share: float = 0.0
    top3_share: float = 0.0


class TemporalBucket(BaseModel):
    """Temporal distribution bucket."""
    bucket_start: str
    bucket_end: str
    count: int


class CurrentWindowSummary(BaseModel):
    """Current window summary aggregates."""
    total_ioc_sightings: int = 0
    distinct_src_ip_count: int = 0
    distinct_dst_ip_count: int = 0
    distinct_country_pairs: int = 0
    protocol_coverage: List[ProtocolCoverage] = Field(default_factory=list)
    sightings_by_log_type: Dict[str, int] = Field(default_factory=dict)
    sightings_by_matched_field: Dict[str, int] = Field(default_factory=dict)
    country_pair_distribution: List[CountryPair] = Field(default_factory=list)
    peer_entity_summary: PeerSummary = Field(default_factory=PeerSummary)
    temporal_distribution: List[TemporalBucket] = Field(default_factory=list)
    protocol_specific_details: Dict[str, Any] = Field(default_factory=dict)


class AdditionalAssets(BaseModel):
    """Additional assets involved."""
    distinct_ip_total: int = 0
    distinct_ip_excluding_trigger: int = 0
    nat_aggregation_note: str = "IP addresses observed at network edge may represent NAT-aggregated traffic."


class ZeekFieldReview(BaseModel):
    """Zeek field review metadata."""
    fields_present: Dict[str, List[str]] = Field(default_factory=dict)
    fields_used_in_summary: Dict[str, List[str]] = Field(default_factory=dict)


class ObservedTTP(BaseModel):
    """Observed TTP entry."""
    technique_id: str
    technique_name: str
    justification: str
    confidence: float


class Confidence(BaseModel):
    """Confidence level and score."""
    level: str = "medium"
    score: float = 0.5


class AIGenerated(BaseModel):
    """AI-generated analysis fields."""
    detailed_communications_analysis: str = ""
    technical_conclusion: str = ""
    confidence: Confidence = Field(default_factory=Confidence)


class RecommendedActions(BaseModel):
    """Recommended actions."""
    immediate: List[str] = Field(default_factory=list)
    validation: List[str] = Field(default_factory=list)
    long_term: List[str] = Field(default_factory=list)


class TicketReport(BaseModel):
    """Complete ticket report model."""
    schema_version: str = "1.0.0"
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    ticket: TicketInfo
    analysis_window: AnalysisWindow
    indicator: IndicatorInfo
    analysis_weighting: AnalysisWeighting = Field(default_factory=AnalysisWeighting)
    historical_ticket_statistics: HistoricalStats = Field(default_factory=HistoricalStats)
    current_window_summary: CurrentWindowSummary = Field(default_factory=CurrentWindowSummary)
    additional_assets_involved: AdditionalAssets = Field(default_factory=AdditionalAssets)
    zeek_field_review: ZeekFieldReview = Field(default_factory=ZeekFieldReview)
    observed_ttps: List[ObservedTTP] = Field(default_factory=list)
    ai_generated: AIGenerated = Field(default_factory=AIGenerated)
    recommended_actions: RecommendedActions = Field(default_factory=RecommendedActions)
    limitations: List[str] = Field(default_factory=lambda: [
        "No raw records are displayed in this report",
        "Records are treated as independent; no session IDs are assumed",
        "Encrypted protocols limit Layer 7 visibility",
        "GeoIP data is taken from embedded log fields (no external enrichment at runtime)"
    ])
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
