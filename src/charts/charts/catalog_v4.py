# Scientific Forensic Catalog v4
# High-Quality Analysis for Professional Threat Hunters

import pandas as pd
from src.charts.factory import ChartFactory
from src.charts.themes import BRAND_TEAL, C_HIGH, C_CRITICAL, BRAND_NAVY, BRAND_GREY
from src.charts.osi_layers import create_forensic_intelligence_timeline
from src.charts.statistical import StatisticalFactory

# =============================================================================
# SCIENTIFIC FORENSIC CATALOG - 24 Advanced Charts
# =============================================================================

CATALOG = {

    # --- PHASE 1: INITIAL TRIAGE ---
    "T1_TOTAL_EVENTS": lambda df: ChartFactory.build_indicator(len(df), "Total Network Events"),
    "T2_HIGH_RISK_COUNT": lambda df: ChartFactory.build_indicator(len(df[df['risk_score'] > 50]) if 'risk_score' in df.columns else 0, "High Risk Events"),
    "T3_EVENT_TIMELINE": lambda df: ChartFactory.build_time_series(df, '@timestamp', None, "Event Volume Over Time", agg='count', color=BRAND_TEAL),
    "T4_ALERT_SUMMARY": lambda df: ChartFactory.build_ranking(df[df['alert.message'].notna()] if 'alert.message' in df.columns else df.head(0), 'alert.message', None, "IDS Alert Summary", color=C_CRITICAL) if 'alert.message' in df.columns and not df[df['alert.message'].notna()].empty else ChartFactory.build_indicator(0, "No IDS Alerts"),

    # --- PHASE 2: ACTOR ATTRIBUTION ---
    "A1_TOP_SOURCES": lambda df: ChartFactory.build_ranking(df, 'source.ip', 'network.bytes', "Top Sources by Traffic Volume", color=BRAND_TEAL),
    "A2_TOP_DESTINATIONS": lambda df: ChartFactory.build_ranking(df, 'destination.ip', 'network.bytes', "Top Destinations by Traffic Volume", color=BRAND_NAVY),
    "A3_NETWORK_MAP": lambda df: ChartFactory.build_network_graph(df, 'source.ip', 'destination.ip', "Connection Map", weight_col='network.bytes'),
    "A4_GEO_ORIGIN": lambda df: ChartFactory.build_geo_map(df, 'enrichment', 'network.bytes', "Traffic Geographic Origin") if 'enrichment' in df.columns else ChartFactory._empty("No GeoIP Data Available"),

    # --- PHASE 3: ATTACK CLASSIFICATION ---
    "C1_PORT_ANALYSIS": lambda df: ChartFactory.build_ranking(df, 'destination.port', None, "Destination Port Usage", color=BRAND_TEAL) if 'destination.port' in df.columns else ChartFactory._empty("Missing Port Data"),
    "C2_PROTOCOL_MIX": lambda df: ChartFactory.build_pie(df, 'network.protocol', "Protocol Distribution"),
    "C3_TCP_FLAGS": lambda df: ChartFactory.build_ranking(df[df['tcp.flags'].notna()] if 'tcp.flags' in df.columns else df.head(0), 'tcp.flags', None, "TCP Flags Distribution", color=C_HIGH) if 'tcp.flags' in df.columns else ChartFactory._empty("No TCP Flags"),
    "C4_DNS_TUNNELING": lambda df: ChartFactory.build_ranking(df[df['dns.question.name'].notna()] if 'dns.question.name' in df.columns else df.head(0), 'dns.question.name', 'network.bytes', "DNS Query Distribution", color=BRAND_NAVY) if 'dns.question.name' in df.columns else ChartFactory._empty("No DNS Data"),
    "C5_HTTP_HOSTS": lambda df: ChartFactory.build_ranking(df[df['url.domain'].notna()] if 'url.domain' in df.columns else df.head(0), 'url.domain', 'network.bytes', "HTTP/HTTPS Destination Analysis", color=C_CRITICAL) if 'url.domain' in df.columns else ChartFactory._empty("No HTTP/HTTPS Data"),
    "C6_RISK_DISTRIBUTION": lambda df: ChartFactory.build_distribution(df, 'risk_score', "Risk Score Spread", color=C_HIGH),

    # --- PHASE 4: THREAT INTELLIGENCE ---
    "I1_PROTOCOL_STACK": lambda df: ChartFactory.build_treemap(df, ['network.transport', 'network.protocol'] if 'network.transport' in df.columns else ['network.protocol'], 'network.bytes', "Protocol Stack Hierarchy"),
    "I2_TRAFFIC_VS_RISK": lambda df: ChartFactory.build_scatter(df, 'network.bytes', 'risk_score', "Traffic vs Risk Correlation", color=C_CRITICAL),
    "I3_MULTI_TRACE": lambda df: ChartFactory.build_parallel_coordinates(df, [dict(label='Source', values='source.ip'), dict(label='Port', values='destination.port'), dict(label='Protocol', values='network.protocol'), dict(label='Bytes', values='network.bytes')], "Multi-Dimensional Trace"),
    "I4_DATA_FLOW": lambda df: ChartFactory.build_sankey(df, 'source.ip', 'destination.ip', "Data Flow Diagram"),
    "I5_RISK_TREND": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'risk_score', "Risk Progression Over Time", agg='max', color=C_CRITICAL),
    "I6_MITRE_TIMELINE": lambda df: create_forensic_intelligence_timeline(df),

    # --- PHASE 5: SCIENTIFIC DEEP DIVE (NEW) ---
    "S1_DNS_ENTROPY": lambda df: StatisticalFactory.build_entropy_field_analysis(df[df['dns.question.name'].notna()] if 'dns.question.name' in df.columns else df.head(0), 'dns.question.name', "DNS Query Entropy (DGA Detection)") or ChartFactory._empty("No DNS Data for Entropy"),
    "S2_BEACONING_ANALYSIS": lambda df: StatisticalFactory.build_beaconing_analysis(df, '@timestamp', "Temporal Beaconing Analysis (C2 Detection)") or ChartFactory._empty("Insufficient Beaconing Data"),
    "S3_FLOW_ASYMMETRY": lambda df: StatisticalFactory.build_flow_asymmetry(df, 'source.ip', 'network.bytes', "Flow Asymmetry Analysis (Exfiltrate Detection)") or ChartFactory._empty("Insufficient Flow Data"),
    "S4_TEMPORAL_HEATMAP": lambda df: StatisticalFactory.build_temporal_heatmap(df, '@timestamp', "Activity Periodicity (Hour vs Day)") or ChartFactory._empty("No Timeline Data")
}

# =============================================================================
# ACTIONABLE DESCRIPTIONS (English)
# =============================================================================

CHART_DESCRIPTIONS = {
    # Phase 5: Scientific
    "S1_DNS_ENTROPY": "WHAT: Randomness score of DNS names | WHY: High entropy (random names) is a classic indicator of DGA/Tunneling | ACTION: Block domains with entropy > 4.5.",
    "S2_BEACONING_ANALYSIS": "WHAT: Inter-arrival time distribution | WHY: Flat lines indicate automated periodic signaling typical of C2 | ACTION: Identify the source IP and isolate for beaconing.",
    "S3_FLOW_ASYMMETRY": "WHAT: Source byte volume distribution | WHY: Detects massive unidirectional transfers | ACTION: Investigate sources with outlier byte-to-count ratios.",
    "S4_TEMPORAL_HEATMAP": "WHAT: Time-of-day activity matrix | WHY: Reveals 24/7 automated patterns vs human activity | ACTION: Identify out-of-hours infrastructure usage.",

    # Triage (Summarized for analyst efficiency)
    "T1_TOTAL_EVENTS": "Total event baseline for scope assessment.",
    "T2_HIGH_RISK_COUNT": "Priority threshold monitor. High count triggers escalation.",
    "T3_EVENT_TIMELINE": "Volume trend analysis to identify attack duration.",
    "T4_ALERT_SUMMARY": "Direct output from IDS rules. High-fidelity signal.",
}

# Populate missing descriptions
for cid in CATALOG:
    if cid not in CHART_DESCRIPTIONS:
        CHART_DESCRIPTIONS[cid] = f"Scientific indicator for {cid.replace('_', ' ').lower()}."

# =============================================================================
# INVESTIGATION PHASES
# =============================================================================

INVESTIGATION_PHASES = {
    "Phase 1: Initial Triage (Scope)": ["T1_TOTAL_EVENTS", "T2_HIGH_RISK_COUNT", "T3_EVENT_TIMELINE", "T4_ALERT_SUMMARY"],
    "Phase 2: Actor Attribution (Entities)": ["A1_TOP_SOURCES", "A2_TOP_DESTINATIONS", "A3_NETWORK_MAP", "A4_GEO_ORIGIN"],
    "Phase 3: Attack Classification (Patterns)": ["C1_PORT_ANALYSIS", "C2_PROTOCOL_MIX", "C3_TCP_FLAGS", "C4_DNS_TUNNELING", "C5_HTTP_HOSTS", "C6_RISK_DISTRIBUTION"],
    "Phase 4: Threat Intelligence (Impact)": ["I1_PROTOCOL_STACK", "I2_TRAFFIC_VS_RISK", "I3_MULTI_TRACE", "I4_DATA_FLOW", "I5_RISK_TREND", "I6_MITRE_TIMELINE"],
    "Phase 5: Scientific Deep Dive (Verification)": ["S1_DNS_ENTROPY", "S2_BEACONING_ANALYSIS", "S3_FLOW_ASYMMETRY", "S4_TEMPORAL_HEATMAP"],
}

def get_chart(chart_id, df):
    fig = None
    desc = CHART_DESCRIPTIONS.get(chart_id, "")
    if chart_id in CATALOG:
        try:
            fig = CATALOG[chart_id](df)
        except Exception as e:
            fig = ChartFactory._empty(f"Analytical Error: {str(e)[:50]}")
    else:
        fig = ChartFactory._empty(f"Chart {chart_id} Not Found")
    return fig, desc

def get_phases():
    return INVESTIGATION_PHASES
