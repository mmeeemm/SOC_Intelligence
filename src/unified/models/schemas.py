"""
Unified Data Models for SOC_Intelligence

TOON-compliant schemas following Ultimate Prompt specification:
- Layer 3+ only (no L1/L2)
- Evidence-based fields
- Normalized representation
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ProtocolType(str, Enum):
    """L3+ protocols only"""
    IP = "ip"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    DNS = "dns"
    TLS = "tls"
    HTTP = "http"
    SMTP = "smtp"
    SSH = "ssh"
    RDP = "rdp"
    SMB = "smb"
    LDAP = "ldap"
    KERBEROS = "kerberos"
    NTP = "ntp"
    DHCP = "dhcp"
    QUIC = "quic"
    FTP = "ftp"
    MQTT = "mqtt"
    UNKNOWN = "unknown"


class TOONEvent(BaseModel):
    """
    Token-Oriented Object Notation Event
    Normalized network event following Ultimate Prompt rules
    """
    # TOON Core Fields
    t: float = Field(..., description="Timestamp (epoch)")
    si: Optional[str] = Field(None, description="Source IP")
    sp: Optional[int] = Field(None, description="Source Port")
    di: Optional[str] = Field(None, description="Destination IP")
    dp: Optional[int] = Field(None, description="Destination Port")
    pr: str = Field(..., description="Protocol")
    
    # Connection Metadata
    bytes_sent: Optional[int] = Field(None, description="Bytes from source")
    bytes_recv: Optional[int] = Field(None, description="Bytes to source")
    packets_sent: Optional[int] = Field(None, description="Packets from source")
    packets_recv: Optional[int] = Field(None, description="Packets to source")
    duration: Optional[float] = Field(None, description="Connection duration (seconds)")
    
    # Protocol-Specific (only if present)
    dns_query: Optional[str] = None
    dns_response: Optional[List[str]] = None
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_uri: Optional[str] = None
    http_user_agent: Optional[str] = None
    http_status: Optional[int] = None
    tls_sni: Optional[str] = None
    tls_ja3: Optional[str] = None
    tls_version: Optional[str] = None
    
    # Enrichment (Zeek)
    zeek_uid: Optional[str] = None
    zeek_service: Optional[str] = None
    zeek_conn_state: Optional[str] = None
    
    # IDS (Snort/Suricata)
    alert_sid: Optional[int] = None
    alert_msg: Optional[str] = None
    alert_priority: Optional[int] = None
    alert_class: Optional[str] = None
    
    # Metadata
    ingestion_time: datetime = Field(default_factory=datetime.utcnow)
    source_file: Optional[str] = None
    
    @validator('si', 'di')
    def drop_null_ips(cls, v):
        """Drop placeholder IPs"""
        if v in ['0.0.0.0', '::', '', None, 'N/A', 'unknown']:
            return None
        return v
    
    @validator('sp', 'dp')
    def drop_null_ports(cls, v):
        """Drop placeholder ports"""
        if v == 0 or v is None:
            return None
        return v
    
    class Config:
        use_enum_values = True


class IOC(BaseModel):
    """Indicator of Compromise"""
    ioc_type: str = Field(..., description="ip, domain, hash, etc.")
    ioc_value: str = Field(..., description="The IOC itself")
    first_seen: datetime
    last_seen: datetime
    sightings: int = 0
    threat_score: float = Field(0.0, ge=0.0, le=1.0)
    sources: List[str] = Field(default_factory=list)


class Ticket(BaseModel):
    """SOC Ticket"""
    ticket_id: str
    ioc: IOC
    trigger_type: str  # "ids_alert", "anomaly", "manual"
    created_at: datetime
    window_start: datetime
    window_end: datetime
    
    # Analysis Results
    verdict: Optional[str] = None  # MALICIOUS/SUSPICIOUS/BENIGN/NEEDS_MORE_EVIDENCE
    severity: Optional[str] = None  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence: Optional[float] = None
    
    # Historical Context
    tp_count: int = 0  # True Positives
    fp_count: int = 0  # False Positives
    historical_threat_ratio: Optional[float] = None
    
    # Report
    report_path: Optional[str] = None
    report_generated: Optional[datetime] = None


class TTP(BaseModel):
    """MITRE ATT&CK Technique"""
    technique_id: str  # T1071.001
    technique_name: str
    tactic: str  # Initial Access, Execution, etc.
    confidence: str  # HIGH/MEDIUM/LOW
    evidence: List[str] = Field(default_factory=list)  # TOON citations
    mitigations: List[str] = Field(default_factory=list)


class WeightedThreatScore(BaseModel):
    """75/25 Weighted Threat Assessment"""
    # Current Window (75%)
    current_volume_score: float
    current_diversity_score: float
    current_pattern_score: float
    current_window_score: float  # Weighted average
    
    # Historical (25%)
    tp_count: int
    fp_count: int
    historical_threat_ratio: float
    historical_score: float
    
    # Final
    weighted_score: float  # (0.75 × current) + (0.25 × historical)
    assessment: str  # THREAT-CONSISTENT/INCONCLUSIVE/FALSE-POSITIVE-CONSISTENT
    
    @validator('weighted_score')
    def calculate_weighted(cls, v, values):
        """Calculate weighted score"""
        current = values.get('current_window_score', 0.0)
        historical = values.get('historical_score', 0.5)  # Default neutral
        return (0.75 * current) + (0.25 * historical)
    
    @validator('assessment')
    def determine_assessment(cls, v, values):
        """Determine assessment from score"""
        score = values.get('weighted_score', 0.0)
        if score >= 0.70:
            return "THREAT-CONSISTENT"
        elif score >= 0.40:
            return "INCONCLUSIVE"
        else:
            return "FALSE-POSITIVE-CONSISTENT"


class AnalysisReport(BaseModel):
    """Complete Analysis Report (14 sections)"""
    report_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    analyst_engine: str = "SOC_Intelligence Ultimate v1.0"
    data_sources: List[str]
    
    # Section 1: Executive Verdict
    verdict: str
    severity: str
    confidence_score: float
    confidence_level: str  # HIGH/MEDIUM/LOW
    rationale: str
    immediate_action: str
    
    # Section 2: Executive Summary
    what_happened: List[str]
    business_risk: str
    decisions_required: List[Dict[str, Any]]
    timeline: Optional[Dict[str, datetime]] = None
    
    # Section 3: Scope & Constraints
    time_window: Dict[str, datetime]
    protocols_observed: List[str]
    limitations: List[str]
    correlation_quality: str
    
    # Section 4: Data Integrity
    record_counts: Dict[str, int]
    coverage_gaps: List[str]
    data_quality_score: Optional[float] = None
    
    # Section 5: Environment Context
    assets: List[Dict[str, Any]] = Field(default_factory=list)
    network_zones: List[str] = Field(default_factory=list)
    
    # Section 6: Observed Facts
    observed_facts: Dict[str, List[str]]
    
    # Section 7: Behavioral Analysis
    behavioral_findings: List[Dict[str, Any]]
    
    # Section 8: Statistical Deviations
    baseline_analysis: Optional[Dict[str, Any]] = None
    
    # Section 9: Threat Assessment
    weighted_threat: WeightedThreatScore
    primary_drivers: List[str]
    alternative_explanations: List[str]
    false_positive_considerations: List[str]
    
    # Section 10: MITRE ATT&CK
    ttps: List[TTP] = Field(default_factory=list)
    
    # Section 11: Impact Assessment
    technical_impact: Dict[str, str]
    business_impact: str
    affected_assets: List[str]
    
    # Section 12: Recommendations
    immediate_actions: List[Dict[str, Any]]
    near_term_actions: List[Dict[str, Any]]
    planned_improvements: List[Dict[str, Any]]
    
    # Section 13: Evidence Index
    evidence_index: Dict[str, List[str]]
    
    # Section 14: Confidence Statement
    overall_confidence: str
    confidence_drivers: List[str]
    confidence_limiters: List[str]
    what_would_increase_confidence: List[str]
    
    class Config:
        use_enum_values = True
