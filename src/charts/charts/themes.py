
import plotly.graph_objects as go

# ==========================================
# 1. PREMIUM CYBER-FORENSIC PALETTE
# ==========================================
BRAND_TEAL = '#00F5E9' # Neon Cyan
BRAND_PURPLE = '#BC13FE' # Cyber Purple
BRAND_BLUE = '#0D6EFD' # Deep Electric Blue
BRAND_NAVY = '#1A1B2E' # Midnight Space
BRAND_GREY = '#94A3B8' # Slate Grey

# Forensic Risk Scale (Glowing)
C_CRITICAL = '#FF003C' # Cyber Red
C_HIGH = '#FF8A00' # Neon Orange
C_MEDIUM = '#FFE600' # Warning Yellow
C_LOW = '#22C55E' # Emerald Green
C_SAFE = '#00E0FF' # Data Blue

# UI Surfaces
BG_GLASS = 'rgba(13, 17, 23, 0.7)' 
BG_PLOT = 'rgba(0,0,0,0)'
TEXT_MAIN = '#F8FAFC'
TEXT_DIM = '#94A3B8'
GRID_COLOR = 'rgba(255, 255, 255, 0.05)' 

# ==========================================
# 2. PLOTLY MASTER TEMPLATE
# ==========================================
def get_blink_template():
    """Returns the Premium Cyber-Forensic Template."""
    return dict(
        layout=go.Layout(
            paper_bgcolor='#0B0B0F',
            plot_bgcolor='#0F0F14',
            font=dict(family="Inter, system-ui, sans-serif", color=TEXT_MAIN, size=12),
            title=dict(
                font=dict(size=18, color=TEXT_MAIN),
                pad=dict(t=20, b=20)
            ),
            xaxis=dict(
                gridcolor=GRID_COLOR,
                zerolinecolor=GRID_COLOR,
                showgrid=True,
                tickfont=dict(color=TEXT_DIM)
            ),
            yaxis=dict(
                gridcolor=GRID_COLOR,
                zerolinecolor=GRID_COLOR,
                showgrid=True,
                tickfont=dict(color=TEXT_DIM)
            ),
            margin=dict(l=60, r=40, t=80, b=60),
            legend=dict(
                bgcolor='rgba(15, 23, 42, 0.5)',
                bordercolor=GRID_COLOR,
                font=dict(color=TEXT_MAIN)
            ),
            autosize=True,
            hoverlabel=dict(
                bgcolor='#1E293B',
                font_size=13
            )
        )
    )

BLINK_TEMPLATE = get_blink_template()
