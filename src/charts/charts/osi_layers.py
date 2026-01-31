
"""OSI Layer Visualization Charts - Legacy Integration"""

import pandas as pd
import logging
from typing import Optional
import plotly.graph_objects as go
from src.charts.themes import BLINK_TEMPLATE

logger = logging.getLogger(__name__)

# OSI Layer colors
OSI_LAYER_COLORS = {
    7: "#e74c3c", # L7-Application - Red
    6: "#9b59b6", # L6-Presentation - Purple
    5: "#3498db", # L5-Session - Blue
    4: "#2ecc71", # L4-Transport - Green
    3: "#f39c12", # L3-Network - Orange
    2: "#1abc9c", # L2-Data Link - Teal
    1: "#95a5a6", # L1-Physical - Gray
}

OSI_LAYER_NAMES = {
    7: "L7-Application",
    6: "L6-Presentation",
    5: "L5-Session",
    4: "L4-Transport",
    3: "L3-Network",
    2: "L2-Data Link",
    1: "L1-Physical",
}

def classify_osi_layer(row: pd.Series) -> int:
    """Classify OSI layer based on osi_stack or port number"""
    if 'osi_stack' in row and pd.notna(row['osi_stack']):
        stack = str(row['osi_stack']).lower()
        if any(p in stack for p in ['http', 'dns', 'tls', 'ssh', 'smb', 'smtp', 'ftp', 'snmp', 'mqtt', 'dnp3', 'modbus']): return 7
        if any(p in stack for p in ['tcp', 'udp', 'sctp', 'quic']): return 4
        if any(p in stack for p in ['ip', 'ipv6', 'icmp', 'arp']): return 3
        if any(p in stack for p in ['eth', 'vlan']): return 2

    if 'destination.port' in row and pd.notna(row['destination.port']):
        port = int(row['destination.port'])
        app_ports = [20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 443, 587, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443]
        if port in app_ports: return 7
        if 1 <= port <= 65535: return 4

    return 3

def add_osi_layer_column(df: pd.DataFrame) -> pd.DataFrame:
    """Add protocol_layer column to dataframe"""
    df_copy = df.copy()
    if not df_copy.empty:
        df_copy['protocol_layer'] = df_copy.apply(classify_osi_layer, axis=1)
    else:
        df_copy['protocol_layer'] = None
    return df_copy

def create_l7_identity_chart(df: pd.DataFrame) -> Optional[go.Figure]:
    """Rank the most frequent L7 Identities"""
    if df.empty: return None

    identities = []
    cols = ['dns.question.name', 'url.domain', 'tls.client.server_name', 'user_agent.original']
    for col in cols:
        if col in df.columns:
            identities.extend(df[col].dropna().tolist())

    if not identities: return None

    s = pd.Series(identities).value_counts().head(10)
    fig = go.Figure(go.Bar(
        x=s.values, y=s.index, orientation='h',
        marker_color="#e74c3c"
    ))

    fig.update_layout(
        title="Top L7 Identities (DNS/SNI/Host)",
        template=BLINK_TEMPLATE,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=400,
        margin=dict(l=40, r=40, t=60, b=40),
        yaxis=dict(autorange="reversed")
    )
    return fig

def create_osi_layer_timeline(df: pd.DataFrame) -> Optional[go.Figure]:
    """Area chart showing traffic over time colored by OSI layer."""
    if df.empty or "@timestamp" not in df.columns: return None

    try:
        df_copy = df.copy()
        df_copy["ts"] = pd.to_datetime(df_copy["@timestamp"], errors="coerce")
        df_copy = df_copy.dropna(subset=["ts"])

        if df_copy.empty: return None

        df_copy = add_osi_layer_column(df_copy)
        duration = (df_copy["ts"].max() - df_copy["ts"].min()).total_seconds()
        
        if duration > 86400 * 7: freq = "D"
        elif duration > 3600 * 24: freq = "H"
        elif duration > 300: freq = "5min"
        else: freq = "5s" if duration > 10 else "1s"

        df_copy = df_copy.set_index("ts")
        layer_counts = df_copy.groupby([pd.Grouper(freq=freq), "protocol_layer"]).size().unstack(fill_value=0)

        fig = go.Figure()
        for layer in [3, 4, 7]:
            if layer in layer_counts.columns:
                fig.add_trace(go.Scatter(
                    x=layer_counts.index, y=layer_counts[layer],
                    fill="tonexty" if layer > 3 else "tozeroy",
                    name=OSI_LAYER_NAMES.get(layer, f"L{layer}"),
                    line=dict(width=0.5, color=OSI_LAYER_COLORS.get(layer)),
                    stackgroup="one"
                ))

        fig.update_layout(
            title="Traffic by OSI Layer (Timeline)",
            template=BLINK_TEMPLATE,
            paper_bgcolor='#0B0B0F',
            plot_bgcolor='#0F0F14',
            height=350,
            xaxis_title=None,
            yaxis_title="Events",
            legend=dict(orientation="h", y=1.1, xanchor='center', x=0.5),
            margin=dict(t=80, b=40, l=60, r=40)
        )
        return fig
    except Exception as e:
        logger.error(f"OSI layer timeline error: {e}")
        return None

def create_osi_layer_distribution(df: pd.DataFrame) -> Optional[go.Figure]:
    """Horizontal bar chart showing event distribution across OSI layers."""
    if df.empty: return None

    try:
        df_copy = add_osi_layer_column(df)
        layer_counts = df_copy["protocol_layer"].value_counts().sort_index()

        layers = [OSI_LAYER_NAMES.get(l, f"L{l}") for l in layer_counts.index]
        colors = [OSI_LAYER_COLORS.get(l, "#666") for l in layer_counts.index]

        fig = go.Figure(data=[go.Bar(
            y=layers, x=layer_counts.values,
            orientation="h", marker_color=colors,
            text=[f"{v:,}" for v in layer_counts.values],
            textposition="outside"
        )])

        fig.update_layout(
            title="OSI Layer Distribution",
            template="plotly_dark",
            height=250,
            xaxis_title="Event Count",
            yaxis_title="",
            showlegend=False,
        )
        return fig
    except Exception as e:
        logger.error(f"OSI layer distribution error: {e}")
        return None

def create_forensic_intelligence_timeline(df: pd.DataFrame) -> Optional[go.Figure]:
    """Advanced timeline for purified sightings."""
    if df.empty or "@timestamp" not in df.columns: return None

    try:
        df_copy = df.copy()
        df_copy["ts"] = pd.to_datetime(df_copy["@timestamp"], errors="coerce")
        df_copy = df_copy.dropna(subset=["ts"])

        if df_copy.empty: return None

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df_copy["ts"],
            y=df_copy["risk_score"] if 'risk_score' in df_copy.columns else [10]*len(df_copy),
            mode="markers",
            marker=dict(
                size=10,
                color=df_copy["risk_score"] if 'risk_score' in df_copy.columns else 10,
                colorscale="Viridis",
                showscale=True
            ),
            name="Forensic Sightings"
        ))

        fig.update_layout(
            title="Forensic Timeline",
            template="plotly_dark",
            height=400,
            margin=dict(l=20, r=20, t=60, b=40)
        )
        return fig
    except Exception as e:
        logger.error(f"Forensic timeline error: {e}")
        return None

def create_osi_layer_stack(df: pd.DataFrame) -> Optional[go.Figure]:
    """Visual stack representing the 7 OSI layers."""
    # Data structure for the stack
    layers = [
        (7, "Application", "#e74c3c", "HTTP, DNS, TLS, SSH"),
        (6, "Presentation", "#9b59b6", "Encryption, Formatting"),
        (5, "Session", "#3498db", "RPC, NetBIOS"),
        (4, "Transport", "#2ecc71", "TCP, UDP"),
        (3, "Network", "#f39c12", "IP, ICMP"),
        (2, "Data Link", "#1abc9c", "Ethernet, ARP"),
        (1, "Physical", "#95a5a6", "Signal, Bitstream")
    ]
    
    fig = go.Figure()
    for i, (num, name, color, protos) in enumerate(reversed(layers)):
        fig.add_trace(go.Bar(
            y=[f"L{num}: {name}"],
            x=[100],
            orientation='h',
            marker_color=color,
            text=f"{protos}",
            textposition='inside',
            hoverinfo='none',
            showlegend=False
        ))

    fig.update_layout(
        title="OSI Model Forensic Map",
        barmode='stack',
        template="plotly_dark",
        height=400,
        xaxis=dict(visible=False),
        yaxis=dict(autorange="reversed"),
        margin=dict(l=10, r=10, t=40, b=10)
    )
    return fig
