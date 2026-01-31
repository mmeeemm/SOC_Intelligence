import pandas as pd
from src.charts.factory import ChartFactory
from src.charts.themes import BRAND_TEAL, C_HIGH, C_CRITICAL, BRAND_NAVY, BRAND_GREY, C_MEDIUM, C_LOW, C_SAFE
from src.charts.osi_layers import (
create_osi_layer_timeline,
create_osi_layer_distribution,
create_forensic_intelligence_timeline,
create_l7_identity_chart,
create_osi_layer_stack
)
from src.charts.statistical import StatisticalFactory
from src.charts.topology import create_fluid_topology

# CATALOG: Maps ID -> Lambda(df -> Figure/Chart)
# Comprehensive 84-Chart Catalog for Incident Analysis
CATALOG = {
# --- A. TIME SERIES (20 charts) ---

"TS_001": lambda df: ChartFactory.build_bandwidth_chart(df, '@timestamp', 'network.bytes', "Bandwidth Usage (Mbps)", color=BRAND_TEAL),
"TS_002": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'risk_score', "Max Risk Impact Over Time", color=C_CRITICAL, agg='max'),
"TS_003": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'duration', "Avg Session Duration", color=BRAND_NAVY, agg='mean'),
"TS_004": lambda df: ChartFactory.build_time_series(df, '@timestamp', None, "Session Density (Ops/min)", color=BRAND_TEAL, agg='count'),
"TS_005": lambda df: ChartFactory.build_time_series(df.nlargest(min(2000, len(df)//10 + 1), 'network.bytes') if 'network.bytes' in df.columns and len(df) > 10 else df.head(100), '@timestamp', 'network.bytes', "High Volume Events (Top 10%)", color=C_CRITICAL, agg='sum'),
"TS_006": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'source.ip', "Unique Active Source IPs", color=BRAND_NAVY, agg='nunique'),
"TS_007": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'destination.ip', "Unique Destinations Over Time", agg='nunique', color=BRAND_NAVY),
"TS_008": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'network.bytes', "Average Packet Size", agg='mean', color=BRAND_TEAL),
"TS_009": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'duration', "Max Session Duration", agg='max'),
"TS_010": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'alert_id', "Alert Rate", agg='count', color=C_HIGH),
"TS_011": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'network.protocol', "Protocol Diversity", agg='nunique', color=BRAND_NAVY),
"TS_012": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'destination.port', "Unique Ports Over Time", agg='nunique'),
"TS_013": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'network.bytes', "Min Packet Size", agg='min', color=BRAND_TEAL),
"TS_015": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'duration', "Avg Connection Time", agg='mean', color=BRAND_NAVY),
"TS_016": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'risk_score', "Risk Trend (Median)", agg='median', color=C_MEDIUM),
"TS_017": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'source.port', "Source Port Changes", agg='nunique'),
"TS_018": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'network.bytes', "Traffic Std Deviation", agg='std', color=BRAND_TEAL),
"TS_019": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'alert_id', "Alert Diversity", agg='nunique', color=C_HIGH),
"TS_020": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'enrichment', "Events with Metadata", agg='count'),

# --- B. DISTRIBUTIONS (15 charts) ---
"DS_001": lambda df: ChartFactory.build_distribution(df, 'network.bytes', "Packet Size Distribution", log_y=True),
"DS_002": lambda df: ChartFactory.build_distribution(df, 'duration', "Session Duration (Log Scale)", log_y=True),
"DS_003": lambda df: ChartFactory.build_distribution(df, 'risk_score', "Risk Distribution (Log Scale)", color=C_CRITICAL, nbins=10, log_y=True),
"DS_004": lambda df: ChartFactory.build_distribution(df, 'source.port', "Source Port Distribution", nbins=30, color=BRAND_NAVY),
"DS_005": lambda df: ChartFactory.build_distribution(df, 'destination.port', "Destination Port Distribution", nbins=30, color=BRAND_TEAL),
"DS_006": lambda df: ChartFactory.build_distribution(df, 'network.protocol', "Protocol Distribution", nbins=20),
"DS_007": lambda df: ChartFactory.build_distribution(df, 'network.bytes', "Volume Distribution (Log Scale)", nbins=40, color=BRAND_TEAL, log_y=True),
"DS_008": lambda df: ChartFactory.build_distribution(df, 'duration', "Connection Duration Dist", log_y=True, nbins=30),
"DS_009": lambda df: ChartFactory.build_distribution(df, 'risk_score', "Risk Score Frequency", nbins=20, color=C_HIGH),
"DS_010": lambda df: ChartFactory.build_distribution(df, 'network.bytes', "Bytes Distribution (Fine)", nbins=60, color=BRAND_TEAL),
"DS_011": lambda df: ChartFactory.build_distribution(df, 'source.port', "Ephemeral Port Usage", nbins=50, color=BRAND_GREY),
"DS_012": lambda df: ChartFactory.build_distribution(df, 'destination.port', "Service Port Distribution", nbins=25, color=BRAND_NAVY),
"DS_013": lambda df: ChartFactory.build_distribution(df, 'duration', "Session Length Histogram", nbins=35),
"DS_015": lambda df: ChartFactory.build_distribution(df, 'risk_score', "Threat Score Spread", nbins=15, color=C_CRITICAL),

# --- C. RANKINGS (15 charts) ---
"RK_001": lambda df: ChartFactory.build_ranking(df, 'source.ip', 'network.bytes', "Top Source IPs (Bytes)", color=BRAND_TEAL),
"RK_002": lambda df: ChartFactory.build_ranking(df, 'destination.ip', 'network.bytes', "Top Dest IPs (Bytes)", color=BRAND_NAVY),
"RK_003": lambda df: ChartFactory.build_ranking(df, 'destination.port', None, "Top Ports (Count)"),
"RK_005": lambda df: ChartFactory.build_ranking(df, 'source.ip', None, "Most Active Sources", color=BRAND_NAVY),
"RK_006": lambda df: ChartFactory.build_ranking(df, 'destination.ip', None, "Most Contacted Destinations", color=BRAND_TEAL),
"RK_007": lambda df: ChartFactory.build_ranking(df, 'source.ip', 'risk_score', "Highest Risk Sources (Peak Score)", color=C_HIGH, agg='max'),
"RK_008": lambda df: ChartFactory.build_ranking(df, 'destination.ip', 'risk_score', "Highest Risk Destinations (Peak Score)", color=C_HIGH, agg='max'),
"RK_009": lambda df: ChartFactory.build_ranking(df, 'network.protocol', None, "Protocol Frequency", top_n=15),
"RK_010": lambda df: ChartFactory.build_ranking(df, 'network.transport', 'network.bytes', "Transport Protocol Volume", color=C_CRITICAL),
"RK_011": lambda df: ChartFactory.build_ranking(df, 'source.port', 'network.bytes', "Top Source Ports (Bytes)", top_n=15, color=BRAND_GREY),
"RK_012": lambda df: ChartFactory.build_ranking(df, 'destination.port', 'network.bytes', "Top Dest Ports (Bytes)", top_n=15, color=BRAND_TEAL),
"RK_013": lambda df: ChartFactory.build_ranking(df, 'source.ip', 'duration', "Max Session Duration (Source)", color=BRAND_NAVY, agg='max'),
"RK_014": lambda df: ChartFactory.build_ranking(df, 'destination.ip', 'duration', "Max Session Duration (Dest)", color=BRAND_TEAL, agg='max'),
"RK_015": lambda df: ChartFactory.build_ranking(df, 'network.protocol', 'risk_score', "Highest Risk Protocols (Peak Score)", color=C_HIGH, top_n=12, agg='max'),

# --- D. CORRELATION / SCATTER (10 charts) ---
"SC_001": lambda df: ChartFactory.build_scatter(df, 'network.bytes', 'duration', "Traffic vs Duration", color_col='risk_score'),
"SC_002": lambda df: ChartFactory.build_scatter(df, 'network.bytes', 'risk_score', "Traffic vs Risk Score", color=BRAND_TEAL),
"SC_003": lambda df: ChartFactory.build_scatter(df, 'duration', 'risk_score', "Duration vs Risk Score", color=C_HIGH),
"SC_004": lambda df: ChartFactory.build_scatter(df, 'source.port', 'destination.port', "Port Correlation", color_col='network.protocol'),
"SC_005": lambda df: ChartFactory.build_scatter(df, 'network.bytes', 'network.bytes', "Volume Analysis", color_col='risk_score'),
"SC_006": lambda df: ChartFactory.build_scatter(df, 'duration', 'network.bytes', "Session Profile", color_col='network.protocol'),
"SC_007": lambda df: ChartFactory.build_scatter(df, 'risk_score', 'network.bytes', "Risk vs Volume", color=C_CRITICAL),
"SC_008": lambda df: ChartFactory.build_scatter(df, 'source.port', 'network.bytes', "Source Port Activity", color_col='risk_score'),
"SC_009": lambda df: ChartFactory.build_scatter(df, 'destination.port', 'duration', "Destination Port Behavior", color=BRAND_NAVY),
"SC_010": lambda df: ChartFactory.build_scatter(df, 'risk_score', 'duration', "Risk-Duration Matrix", color=C_HIGH),
"SC_011": lambda df: ChartFactory.build_scatter(df, '@timestamp', 'destination.port', "Interactive Forensic Timeline (Time vs Port)", color_col='network.protocol', size_col='network.bytes'),

# --- E. INDICATORS / KPIs (5 charts) ---
"IN_001": lambda df: ChartFactory.build_indicator(len(df), "Total Events", format_str=",.0f"),
"IN_002": lambda df: ChartFactory.build_indicator(df['network.bytes'].sum() if not df.empty else 0, "Total Traffic", suffix=" B", format_str=",.0f"),
"IN_003": lambda df: ChartFactory.build_indicator(len(df[df['risk_score'] > 50]) if not df.empty else 0, "High Risk Events", format_str=",.0f"),
"IN_004": lambda df: ChartFactory.build_indicator(df['risk_score'].mean() if not df.empty else 0, "Avg Risk Score", format_str=".1f"),
"IN_005": lambda df: ChartFactory.build_indicator(df['source.ip'].nunique() if not df.empty else 0, "Unique Sources", format_str=",.0f"),

# --- F. GEO MAPS (4 charts) ---
"GM_001": lambda df: ChartFactory.build_geo_map(df, 'enrichment', 'network.bytes', "Traffic by Country", color=BRAND_TEAL) if 'enrichment' in df.columns else ChartFactory._empty("Traffic by Country (No geo data)"),
"GM_002": lambda df: ChartFactory.build_geo_map(df, 'enrichment', 'risk_score', "Threats by Country", color=C_CRITICAL) if 'enrichment' in df.columns else ChartFactory._empty("Threats by Country (No geo data)"),
"GM_003": lambda df: ChartFactory.build_geo_map(df, 'enrichment', None, "Destination Countries", color=BRAND_NAVY) if 'enrichment' in df.columns else ChartFactory._empty("Destination Countries (No geo data)"),
# GM_004 removed (duplicate of GM_001)

# --- G. NETWORK GRAPHS (3 charts) ---
"NG_001": lambda df: ChartFactory.build_network_graph(df, 'source.ip', 'destination.ip', "Source-Dest Network", weight_col='network.bytes', max_nodes=30, color=BRAND_TEAL),
"NG_002": lambda df: ChartFactory.build_network_graph(df, 'source.ip', 'destination.port', "Source-Port Topology", max_nodes=40, color=BRAND_NAVY),
"NG_003": lambda df: ChartFactory.build_network_graph(df.nlargest(500, 'network.bytes') if 'network.bytes' in df.columns else df.head(500), 'source.ip', 'destination.ip', "High-Volume Network (Top 500)", weight_col='network.bytes', max_nodes=25, color=C_HIGH),
"NG_004": lambda df: create_fluid_topology(df, 'source.ip', 'destination.ip', "Fluid Net Discovery (Pyvis)", weight_col='network.bytes'),

# --- H. OSI LAYER ANALYSIS (3 charts) ---
"OSI_001": lambda df: create_osi_layer_timeline(df),
"OSI_002": lambda df: create_osi_layer_distribution(df),
"OSI_003": lambda df: create_l7_identity_chart(df),

# --- I. PROTOCOL STACKING (New Phase 10) ---
"ST_001": lambda df: ChartFactory.build_ranking(df.assign(**{'osi_stack': df['osi_stack'].astype(str).str[:30]}) if 'osi_stack' in df.columns else df, 'osi_stack', None, "Common Protocol Stacks", color=BRAND_TEAL),
"ST_011": lambda df: ChartFactory.build_ranking(df, 'dns.question.name', 'network.bytes', "Traffic per DNS Query", color="#e74c3c"),
"ST_003": lambda df: ChartFactory.build_ranking(df, 'url.domain', 'network.bytes', "Traffic per HTTP Host", color="#e74c3c"),

# --- STATISTICS & DENSITY (Altair Engine) ---
"ST_004": lambda df: StatisticalFactory.build_temporal_heatmap(df, '@timestamp', "Event Density (Hour vs Day)"),
"ST_005": lambda df: StatisticalFactory.build_risk_density(df, 'destination.port', 'network.bytes', "Port vs Traffic Density"),
"ST_006": lambda df: StatisticalFactory.build_protocol_aesthetic_bar(df, 'network.protocol', 'network.bytes', "Protocol Volume (Aesthetic)"),

# --- J. FORENSIC INTELLIGENCE (Phase 16) ---
"FI_001": lambda df: create_forensic_intelligence_timeline(df),

# --- LEGACY INTEGRATION (LG_*) ---
"LG_001": lambda df: ChartFactory.build_treemap(df, ['network.transport', 'osi_stack', 'destination.port'], 'network.bytes', "Protocol Hierarchy (Architectural)"),
"LG_002": lambda df: ChartFactory.build_pie(df, 'network.protocol', "Protocol Distribution"),
"LG_003": lambda df: ChartFactory.build_sankey(df, 'source.ip', 'destination.ip', "Network Flow Dynamics"),
"LG_004": lambda df: ChartFactory.build_parallel_coordinates(df, [
dict(label='Source', values='source.ip'),
dict(label='Dst Port', values='destination.port'),
dict(label='Protocol', values='network.protocol'),
dict(label='Size', values='network.bytes')
], "Multidimensional Forensic Tracing"),
"LG_005": lambda df: ChartFactory.build_radar(df, 'destination.port', "Port Activity Radar (Freq/Vol/Risk)"),
"LG_006": lambda df: ChartFactory.build_anomaly_scatter(df, '@timestamp', 'network.bytes', 'risk_score', "Statistical Outlier Analysis"),
"LG_007": lambda df: create_osi_layer_stack(df),
"LG_009": lambda df: ChartFactory.build_parallel_coordinates(df, [
dict(label='Duration (s)', values='duration'),
dict(label='Data Volume (B)', values='network.bytes'),
dict(label='Dst Port', values='destination.port'),
dict(label='Risk Score', values='risk_score'),
dict(label='Protocol', values='network.protocol')
], "L4 Forensic Path Tracer (Interactive)"),
"ST_012": lambda df: StatisticalFactory.build_serpentine_timeline(df, '@timestamp', 'destination.ip', "Incident Narrative (Serpentine Timeline)"),

# --- ANTIGRAVITY GATEWAY-ONLY CATALOG (Aliases & New Defs) ---
# A. Time Series
"Total_Network_Events_Over_Time": lambda df: ChartFactory.build_time_series(df, '@timestamp', None, "Total Network Events", agg='count', color=BRAND_NAVY),
# Total_Alerts_Over_Time removed (duplicate of TS_010)
"Sessions_Count_Over_Time": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'source.ip', "Active Sessions (Est)", agg='count'),
"Bytes_In_vs_Bytes_Out_Over_Time": lambda df: ChartFactory.build_time_series(df, '@timestamp', 'network.bytes', "Traffic Volume (Bytes)", color=BRAND_TEAL),

# C. Ranked Comparative
# C. Ranked Comparative
# Top_Source_IPs_By_Bytes_Out removed (duplicate of RK_001)
# Top_Destination_IPs_By_Bytes_Out removed (duplicate of RK_002)
"Top_Protocols_By_Volume": lambda df: ChartFactory.build_ranking(df, 'network.protocol', 'network.bytes', "Top Protocols (Bytes)", color=BRAND_TEAL),
"Top_Snort_SIDs": lambda df: ChartFactory.build_ranking(df, 'alert.message', None, "Top Snort Alerts", color=C_CRITICAL),

# B. Distributions
"Protocol_Frequency_Distribution": lambda df: ChartFactory.build_distribution(df, 'network.protocol', "Protocol Distribution"),
"Session_Duration_Distribution": lambda df: ChartFactory.build_distribution(df, 'duration', "Session Duration"),

# E. Network Graph
"Source_Destination_Network_Graph": lambda df: ChartFactory.build_network_graph(df, 'source.ip', 'destination.ip', "Connection Graph", max_nodes=50),
}

# CHART_DESCRIPTIONS: Short forensic purpose for each chart
CHART_DESCRIPTIONS = {
"TS_001": "Bandwidth consumption rate (Mbps) relative to network capacity.",
"TS_002": "Peak risk score per minute (detects burst attacks).",
"TS_003": "Session duration trends (helps detect C2 beaconing).",
"TS_004": "Volume of established sessions (excludes fragmented packets).",
"TS_005": "Critical security events (High Risk or IDS Severity 1).",
"TS_006": "Distinct count of active source IP addresses.",
"RK_001": "Top Volume Sources (Total In+Out).",
"RK_002": "Top Volume Destinations (Total In+Out).",
"RK_003": "Most Frequent Destination Ports.",
"RK_005": "Most Frequent Sources (Connection Count).",
"RK_006": "Most targeted addresses by different sources.",
"RK_007": "Highest Risk Sources (Peak Score).",
"RK_008": "Highest Risk Destinations (Peak Score).",
"DS_001": "Packet size distribution to detect unusual patterns.",
"DS_002": "Session duration distribution to detect suspicious long sessions.",
"DS_003": "Risk score distribution to classify threat severity.",
"DS_004": "Source port distribution (helps detect port scanning).",
"DS_005": "Destination port distribution for active network services.",
"DS_006": "Protocol distribution used in recorded sessions.",
"DS_007": "Total data volume distribution per communication session.",
"DS_009": "Risk score frequency to determine general threat patterns.",
"NG_001": "Source-Destination relationship map for network structure visualization.",
"NG_002": "Source-Port relationships to discover utilized services.",
"NG_003": "High-risk communication network only to isolate threats.",
"SC_001": "Correlation between data volume and session duration (detects tunnels).",
"SC_002": "Correlation analysis between data volume and risk score.",
"SC_003": "Correlation analysis between session duration and risk score.",
"SC_004": "Correlation between source and destination ports to detect attack patterns.",
"SC_005": "Symmetric data volume analysis to detect suspicious asymmetry.",
"SC_011": "Interactive timeline linking time, ports, and data volume.",
"LG_001": "Hierarchical visualization of used protocols and ports.",
"LG_002": "Threat ratios divided by severity level (Safe, Medium, Critical).",
"LG_003": "Data flow diagram showing kinetic paths between addresses.",
"LG_004": "Tracing multi-path connections (Source, Port, Volume).",
"LG_005": "Radar showing activity concentration on specific service ports.",
"LG_006": "Detection of statistical outliers (Anomalies) in data volume.",
"LG_007": "Display of OSI layers and compatibility with detected protocols.",
"LG_009": "L4 Forensic Tracer: Correlates time, volume, port, and risk to detect session anomalies (e.g., C2 or Exfil).",
"ST_012": "Serpentine Incident Narrative: Interactive flow showing the sequence of forensic events."
}

def get_chart(chart_id, df):
    """Retrieve chart and optional description."""
    fig = None
    desc = CHART_DESCRIPTIONS.get(chart_id, "")

    if chart_id in CATALOG:
        fig = CATALOG[chart_id](df)
    else:
        fig = ChartFactory._empty(f"Chart {chart_id} Not Found")

        return fig, desc

