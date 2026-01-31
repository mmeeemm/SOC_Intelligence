
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
from src.charts.themes import BLINK_TEMPLATE, BRAND_TEAL, BRAND_NAVY, BRAND_GREY, C_CRITICAL, C_HIGH, BRAND_BLUE

class ChartFactory:
    """
    Builder Pattern for generating standardized charts.
    """

    @staticmethod
    def _empty(title: str):
        fig = go.Figure()
        fig.update_layout(
            title=title,
            template=BLINK_TEMPLATE,
            annotations=[dict(text="No Data Available for this Dimension", showarrow=False, font=dict(size=20))],
            paper_bgcolor='#0B0B0F',
            plot_bgcolor='#0F0F14'
        )
        return fig

    @staticmethod
    def build_bandwidth_chart(df: pd.DataFrame, time_col: str, metric_col: str, title: str, 
                              color=BRAND_TEAL, interval='1min'):
        """Premium Mbps Bandwidth chart with automated forensic thresholding."""
        if df.empty or time_col not in df.columns or metric_col not in df.columns:
            return ChartFactory._empty(title)

        try:
            df_copy = df.copy()
            df_copy[time_col] = pd.to_datetime(df_copy[time_col], errors='coerce', utc=True)
            df_copy = df_copy.dropna(subset=[time_col])

            if df_copy.empty: return ChartFactory._empty(title)

            # Auto-adjust interval
            duration = (df_copy[time_col].max() - df_copy[time_col].min()).total_seconds()
            if duration < 300: interval = '5s' if duration > 10 else '1s'

            pd_interval = pd.to_timedelta(interval)
            interval_seconds = pd_interval.total_seconds() or 1

            df_resampled = df_copy.set_index(time_col).resample(interval)[metric_col].sum().fillna(0).reset_index()
            df_resampled['mbps'] = (df_resampled[metric_col] * 8) / (interval_seconds * 1_000_000)

            fig = px.area(df_resampled, x=time_col, y='mbps', title=title, color_discrete_sequence=[color])
            fig.update_traces(fill='tozeroy', line=dict(width=3, color=color))

            fig.update_layout(
                template=BLINK_TEMPLATE,
                paper_bgcolor='#0B0B0F',
                plot_bgcolor='#0F0F14',
                xaxis_title=None,
                yaxis_title='Bandwidth (Mbps)',
                hovermode='x unified',
                height=450
            )
            return fig
        except Exception as e:
            return ChartFactory._empty(f"{title} (Error: {e})")

    @staticmethod
    def build_time_series(df: pd.DataFrame, time_col: str, metric_col: str, title: str, 
                          color=BRAND_TEAL, interval='1min', agg='sum', render_type='area'):
        """Generate Time Series Chart (Line or Area)."""
        if df.empty or time_col not in df.columns:
            return ChartFactory._empty(title)

        try:
            df_copy = df.copy()
            df_copy[time_col] = pd.to_datetime(df_copy[time_col], errors='coerce', utc=True)
            df_copy = df_copy.dropna(subset=[time_col])
            
            if df_copy.empty: return ChartFactory._empty(title)

            # Auto-adjust interval
            duration = (df_copy[time_col].max() - df_copy[time_col].min()).total_seconds()
            if duration < 300: interval = '5s' if duration > 10 else '1s'

            if metric_col is None or metric_col not in df_copy.columns:
                d = df_copy.set_index(time_col).resample(interval).size().reset_index(name='count')
                metric_col = 'count'
            else:
                df_copy[metric_col] = pd.to_numeric(df_copy[metric_col], errors='coerce').fillna(0)
                d = df_copy.set_index(time_col).resample(interval)[metric_col].agg(agg).fillna(0).reset_index()

            if render_type == 'area':
                fig = px.area(d, x=time_col, y=metric_col, title=title, color_discrete_sequence=[color])
            else:
                fig = px.line(d, x=time_col, y=metric_col, title=title, color_discrete_sequence=[color])

            fig.update_layout(
                template=BLINK_TEMPLATE,
                paper_bgcolor='#0B0B0F',
                plot_bgcolor='#0F0F14',
                hovermode='x unified',
                height=450
            )
            return fig
        except Exception as e:
            return ChartFactory._empty(f"{title} (Error: {e})")

    @staticmethod
    def build_distribution(df: pd.DataFrame, col: str, title: str, color=BRAND_TEAL, nbins=50):
        """Generate Histogram."""
        if df.empty or col not in df.columns:
            return ChartFactory._empty(title)

        fig = px.histogram(df, x=col, nbins=nbins, title=title, color_discrete_sequence=[color])
        fig.update_layout(template=BLINK_TEMPLATE, paper_bgcolor='#0B0B0F', plot_bgcolor='#0F0F14', height=450)
        return fig

    @staticmethod
    def build_ranking(df: pd.DataFrame, cat_col: str, metric_col: str, title: str, top_n=10):
        """Generate Horizontal Bar Chart."""
        if df.empty or cat_col not in df.columns:
            return ChartFactory._empty(title)

        if metric_col and metric_col in df.columns:
            d = df.groupby(cat_col)[metric_col].sum().reset_index()
            y_val = metric_col
        else:
            d = df[cat_col].value_counts().reset_index()
            d.columns = [cat_col, 'count']
            y_val = 'count'

        top = d.nlargest(top_n, y_val)
        fig = px.bar(top, y=cat_col, x=y_val, orientation='h', title=title, color_discrete_sequence=[BRAND_TEAL])
        fig.update_layout(template=BLINK_TEMPLATE, paper_bgcolor='#0B0B0F', plot_bgcolor='#0F0F14', height=450)
        return fig

    @staticmethod
    def build_indicator(value, title: str, suffix=""):
        """Generate KPI Indicator (Gauge/Number)."""
        fig = go.Figure()
        fig.add_trace(go.Indicator(
            mode="number",
            value=value,
            title={'text': title},
            number={'suffix': suffix},
            domain={'x': [0, 1], 'y': [0, 1]}
        ))
        fig.update_layout(template=BLINK_TEMPLATE, paper_bgcolor="#0B0B0F", plot_bgcolor="#0F0F14", height=200)
        return fig

    @staticmethod
    def build_data_table(df: pd.DataFrame, title: str, columns=None, max_rows=100):
        """Generate styled data table."""
        if df.empty: return pd.DataFrame({"Status": ["No Data Available"]})
        display_df = df.head(max_rows)
        if columns:
            available_cols = [c for c in columns if c in display_df.columns]
            if available_cols: display_df = display_df[available_cols]
        return display_df

    @staticmethod
    def build_sunburst(df: pd.DataFrame, path: list, title: str):
        """Generate Sunburst chart for hierarchical data."""
        if df.empty: return ChartFactory._empty(title)
        try:
            fig = px.sunburst(df, path=path, title=title)
            fig.update_layout(template=BLINK_TEMPLATE, paper_bgcolor="#0B0B0F", plot_bgcolor="#0F0F14", height=500)
            return fig
        except Exception as e:
            return ChartFactory._empty(f"{title} (Error: {e})")

    @staticmethod
    def build_sankey(df: pd.DataFrame, source_col: str, target_col: str, title: str):
        """Generate Sankey diagram for flow visualization."""
        if df.empty or source_col not in df.columns or target_col not in df.columns:
            return ChartFactory._empty(title)

        try:
            flow_df = df.groupby([source_col, target_col]).size().reset_index(name='value')
            all_labels = list(set(flow_df[source_col].unique()) | set(flow_df[target_col].unique()))
            label_map = {label: i for i, label in enumerate(all_labels)}

            fig = go.Figure(data=[go.Sankey(
                node=dict(pad=15, thickness=20, label=all_labels, color=BRAND_TEAL),
                link=dict(
                    source=flow_df[source_col].map(label_map),
                    target=flow_df[target_col].map(label_map),
                    value=flow_df['value']
                )
            )])
            fig.update_layout(template=BLINK_TEMPLATE, title=title, height=500, paper_bgcolor='#0B0B0F', plot_bgcolor='#0F0F14')
            return fig
        except Exception as e:
            return ChartFactory._empty(f"{title} (Error: {e})")
