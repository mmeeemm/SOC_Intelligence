
import altair as alt
import pandas as pd
import numpy as np
from typing import Optional
import math

class StatisticalFactory:
    """
    Vega-Altair Factory for Aesthetic Statistical Visualizations.
    Complements Plotly by focusing on density and correlation.
    """

    @staticmethod
    def build_temporal_heatmap(df: pd.DataFrame, time_col: str, title: str):
        """Aesthetic Heatmap: Hour of Day vs Day of Week."""
        if df.empty: return None

        try:
            df_copy = df.copy()
            df_copy[time_col] = pd.to_datetime(df_copy[time_col])
            df_copy['day'] = df_copy[time_col].dt.day_name()
            df_copy['hour'] = df_copy[time_col].dt.hour

            chart = alt.Chart(df_copy).mark_rect().encode(
                x=alt.X('hour:O', title='Hour of Day'),
                y=alt.Y('day:O', title='Day of Week', sort=['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']),
                color=alt.Color('count():Q', scale=alt.Scale(scheme='viridis'), title='Event Count'),
                tooltip=['day', 'hour', 'count()']
            ).properties(
                title=title, width='container', height=300
            ).configure_view(strokeWidth=0).configure_axis(
                grid=False, labelColor='#94A3B8', titleColor='#F8FAFC'
            ).configure_title(color='#F8FAFC')

            return chart
        except:
            return None

    @staticmethod
    def build_risk_density(df: pd.DataFrame, x_col: str, y_col: str, title: str):
        """Binned 2D Density Plot for high-volume correlation."""
        if df.empty or x_col not in df.columns or y_col not in df.columns: return None

        try:
            df_valid = df.dropna(subset=[x_col, y_col]).copy()
            if df_valid.empty or len(df_valid) < 2: return None

            chart = alt.Chart(df_valid).mark_rect().encode(
                x=alt.X(x_col, bin=alt.Bin(maxbins=40), title=x_col),
                y=alt.Y(y_col, bin=alt.Bin(maxbins=40), title=y_col),
                color=alt.Color('count():Q', scale=alt.Scale(scheme='plasma'), title='Count'),
                tooltip=['count()']
            ).properties(
                title=title, width='container', height=350
            ).configure_view(strokeWidth=0).configure_axis(
                labelColor='#94A3B8', titleColor='#F8FAFC'
            ).configure_title(color='#F8FAFC')
            return chart
        except:
            return None

    @staticmethod
    def build_protocol_aesthetic_bar(df: pd.DataFrame, cat_col: str, metric_col: str, title: str):
        """Clean, aesthetic bar chart with interactive selection."""
        if df.empty or cat_col not in df.columns: return None

        try:
            df_valid = df.dropna(subset=[cat_col]).copy()
            if df_valid.empty: return None

            selection = alt.selection_point(fields=[cat_col], bind='legend')
            chart = alt.Chart(df_valid).mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
                x=alt.X(cat_col, sort='-y', title=None),
                y=alt.Y(f'sum({metric_col}):Q' if metric_col else 'count():Q', title='Volume'),
                color=alt.Color(cat_col, scale=alt.Scale(scheme='tableau10')),
                opacity=alt.condition(selection, alt.value(1), alt.value(0.2)),
                tooltip=[cat_col, alt.Tooltip(f'sum({metric_col}):Q' if metric_col else 'count():Q', format=',.0f')]
            ).add_params(selection).properties(
                title=title, width='container', height=300
            ).configure_view(strokeWidth=0).configure_axis(
                labelColor='#94A3B8', titleColor='#F8FAFC'
            ).configure_title(color='#F8FAFC').interactive()

            return chart
        except:
            return None

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon Entropy of a string."""
        if not text or not isinstance(text, str): return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    @staticmethod
    def build_entropy_field_analysis(df: pd.DataFrame, col: str, title: str):
        """Analyze Shannon Entropy of a specific field."""
        if df.empty or col not in df.columns: return None

        try:
            d = df.copy()
            d['entropy'] = d[col].apply(StatisticalFactory.calculate_entropy)
            chart = alt.Chart(d).mark_circle(size=60).encode(
                x=alt.X('index:Q' if 'index' in d.columns else '@timestamp:T', title='Timeline'),
                y=alt.Y('entropy:Q', title='Shannon Entropy'),
                color=alt.Color('entropy:Q', scale=alt.Scale(scheme='redyellowgreen', reverse=True)),
                tooltip=[col, 'entropy']
            ).properties(title=title, width='container', height=300).configure_axis(
                labelColor='#94A3B8', titleColor='#F8FAFC'
            ).configure_title(color='#F8FAFC')
            return chart
        except:
            return None

    @staticmethod
    def build_beaconing_analysis(df: pd.DataFrame, time_col: str, title: str):
        """Autocorrelation to detect periodic C2 signaling (Beaconing)."""
        if df.empty or time_col not in df.columns: return None

        try:
            d = df.filter([time_col]).copy()
            d[time_col] = pd.to_datetime(d[time_col])
            d = d.sort_values(time_col)
            d['delta'] = d[time_col].diff().dt.total_seconds().fillna(0)
            d = d[d['delta'] > 0.1].head(100)

            if len(d) < 5: return None

            chart = alt.Chart(d).mark_line(point=True).encode(
                x=alt.X('index:Q' if 'index' in d.columns else f'{time_col}:T', title='Sequence'),
                y=alt.Y('delta:Q', title='Interval (s)', scale=alt.Scale(type='log')),
                color=alt.value('#00F5E9'),
                tooltip=['delta']
            ).properties(title=title, width='container', height=300).configure_axis(
                labelColor='#94A3B8', titleColor='#F8FAFC'
            ).configure_title(color='#F8FAFC')
            return chart
        except:
            return None

    @staticmethod
    def build_flow_asymmetry(df: pd.DataFrame, src_col: str, bytes_col: str, title: str):
        """Asymmetry analysis: Detects massive data exfiltration patterns."""
        if df.empty or src_col not in df.columns or bytes_col not in df.columns: return None

        try:
            summary = df.groupby(src_col)[bytes_col].agg(['sum', 'count', 'mean']).reset_index()
            summary.columns = [src_col, 'total_bytes', 'event_count', 'avg_bytes']
            summary = summary.sort_values('total_bytes', ascending=False).head(15)

            chart = alt.Chart(summary).mark_bar().encode(
                x=alt.X('total_bytes:Q', title='Total Bytes'),
                y=alt.Y(f'{src_col}:N', sort='-x', title='Source'),
                color=alt.Color('avg_bytes:Q', scale=alt.Scale(scheme='magma')),
                tooltip=[src_col, 'total_bytes', 'event_count', 'avg_bytes']
            ).properties(title=title, width='container', height=400).configure_axis(
                labelColor='#94A3B8', titleColor='#F8FAFC'
            ).configure_title(color='#F8FAFC')
            return chart
        except:
            return None
