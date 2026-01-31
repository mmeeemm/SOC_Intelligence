
import pandas as pd
from pyvis.network import Network
import tempfile
import os

def create_fluid_topology(df: pd.DataFrame, source_col: str, target_col: str, title: str, weight_col: str = None, max_nodes=50):
    """
    Creates a physics-based, draggable network graph using Pyvis.
    Returns the HTML content as a string.
    """
    if df.empty or source_col not in df.columns or target_col not in df.columns:
        return None

    try:
        # Sample data
        d = df[[source_col, target_col]].copy()
        if weight_col and weight_col in df.columns:
            d['weight'] = df[weight_col]
        else:
            d['weight'] = 1

        d = d.head(max_nodes * 3)

        # Initialize Pyvis Network
        net = Network(height="500px", width="100%", bgcolor="#0B0B0F", font_color="white", heading=title)
        net.force_atlas_2based()

        # Add nodes and edges
        nodes = set(d[source_col].unique()) | set(d[target_col].unique())
        top_nodes = set(list(nodes)[:max_nodes])

        for node in top_nodes:
            net.add_node(node, label=str(node), title=str(node), color="#00F5E9")

        for _, row in d.iterrows():
            if row[source_col] in top_nodes and row[target_col] in top_nodes:
                net.add_edge(row[source_col], row[target_col], value=float(row['weight']), color="#334155")

        # Generate HTML
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
            tmp_path = tmp.name
            net.save_graph(tmp_path)
            with open(tmp_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            os.unlink(tmp_path)
            return html_content

    except Exception as e:
        return f"<div>Error generating Fluid Topology: {e}</div>"
