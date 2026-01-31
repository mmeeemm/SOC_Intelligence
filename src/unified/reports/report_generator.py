"""
Report Generator for SOC_Intelligence

Generates professional 14-section enterprise reports following Ultimate Prompt spec.
Supports HTML, JSON, and Markdown output formats.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import json

from unified.models.schemas import AnalysisReport, TOONEvent, WeightedThreatScore, TTP
from unified.ai.llm_service import LocalLLMService
from unified.analysis.ttp_mapper import TTPMapper
from unified.analysis.anomaly_detector import AnomalyDetector
from unified.db.duckdb_adapter import DuckDBAdapter
from collections import Counter

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Enterprise-grade SOC report generation
    
    Features:
    - 14-section structure (Ultimate Prompt)
    - 75/25 weighted threat analysis
    - MITRE ATT&CK mapping
    - Multiple output formats
    """
    
    def __init__(
        self,
        llm: LocalLLMService,
        ttp_mapper: TTPMapper,
        anomaly_detector: AnomalyDetector,
        db: DuckDBAdapter
    ):
        self.llm = llm
        self.ttp_mapper = ttp_mapper
        self.anomaly_detector = anomaly_detector
        self.db = db
    
    def generate_report(
        self,
        events: List[TOONEvent],
        ticket_context: Optional[Dict] = None,
        output_format: str = "markdown"
    ) -> str:
        """
        Generate complete analysis report
        
        Args:
            events: TOON normalized events
            ticket_context: Optional ticket metadata
            output_format: "markdown", "html", or "json"
        
        Returns:
            Generated report in requested format
        """
        
        logger.info(f"Generating {output_format} report for {len(events)} events")
        
        # Step 1: Get historical stats (for 75/25 weighting)
        historical_stats = None
        if ticket_context and ticket_context.get('ioc_value'):
            historical_stats = self.db.get_historical_stats(ticket_context['ioc_value'])
            logger.info(f"Historical stats: {historical_stats}")
        
        # Step 2: Detect TTPs
        ttps = self.ttp_mapper.infer_techniques(events)
        logger.info(f"Detected {len(ttps)} TTPs")
        
        # Step 3: Detect anomalies
        anomalies = self.anomaly_detector.detect_anomalies(events)
        logger.info(f"Detected {anomalies['total_anomalies']} anomalies")
        
        # Step 4: Generate with LLM
        report_md = self.llm.generate_analysis(
            toon_events=events,
            ticket_context=ticket_context,
            historical_stats=historical_stats,
            detected_ttps=ttps
        )
        
        # Step 5: Format output
        if output_format == "markdown":
            return report_md
        elif output_format == "html":
            return self._convert_to_html(report_md, events, ttps, anomalies)
        elif output_format == "json":
            return self._convert_to_json(report_md, events, ttps, anomalies, historical_stats)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def _prepare_chart_data(self, events: List[TOONEvent], ttps: List[TTP]) -> Dict:
        """Prepare data for Chart.js visualizations"""
        
        # Chart 1: Traffic Volume Over Time
        time_buckets = {}
        for event in events:
            hour = datetime.fromtimestamp(event.t).strftime('%H:00')
            bytes_total = (event.bytes_sent or 0) + (event.bytes_recv or 0)
            time_buckets[hour] = time_buckets.get(hour, 0) + (bytes_total / 1024 / 1024)  # MB
        
        traffic_volume = {
            'labels': sorted(time_buckets.keys()),
            'volumes': [time_buckets[k] for k in sorted(time_buckets.keys())]
        }
        
        # Chart 2: Protocol Distribution
        protocol_counts = Counter(e.pr for e in events)
        protocol_distribution = {
            'protocols': list(protocol_counts.keys())[:5],  # Top 5
            'counts': [protocol_counts[p] for p in list(protocol_counts.keys())[:5]]
        }
        
        # Chart 3: Risk Timeline (based on alerts)
        risk_buckets = {}
        for event in events:
            hour = datetime.fromtimestamp(event.t).strftime('%H:00')
            if hour not in risk_buckets:
                risk_buckets[hour] = {'high': 0, 'suspicious': 0, 'normal': 0}
            
            if event.alert_msg:
                if event.alert_priority and event.alert_priority >= 1:
                    risk_buckets[hour]['high'] += 1
                else:
                    risk_buckets[hour]['suspicious'] += 1
            else:
                risk_buckets[hour]['normal'] += 1
        
        risk_timeline = {
            'time_buckets': sorted(risk_buckets.keys()),
            'high_risk': [risk_buckets[h]['high'] for h in sorted(risk_buckets.keys())],
            'suspicious': [risk_buckets[h]['suspicious'] for h in sorted(risk_buckets.keys())],
            'normal': [risk_buckets[h]['normal'] for h in sorted(risk_buckets.keys())]
        }
        
        # Chart 4: Top Talkers
        ip_packets = Counter(e.si for e in events if e.si)
        top_ips = ip_packets.most_common(5)
        top_talkers = {
            'ips': [ip for ip, _ in top_ips],
            'packet_counts': [count for _, count in top_ips]
        }
        
        # Chart 5: Connection States (Zeek)
        state_counts = Counter(e.zeek_conn_state for e in events if e.zeek_conn_state)
        connection_states = {
            'states': list(state_counts.keys())[:5],
            'counts': [state_counts[s] for s in list(state_counts.keys())[:5]]
        }
        
        # Chart 6: MITRE ATT&CK Heatmap
        tactic_counts = Counter(ttp.tactic for ttp in ttps)
        mitre_heatmap = {
            'tactics': list(tactic_counts.keys()),
            'technique_counts': list(tactic_counts.values())
        }
        
        return {
            'traffic_volume': traffic_volume,
            'protocol_distribution': protocol_distribution,
            'risk_timeline': risk_timeline,
            'top_talkers': top_talkers,
            'connection_states': connection_states,
            'mitre_heatmap': mitre_heatmap
        }
    
    def _convert_to_html(
        self,
        report_md: str,
        events: List[TOONEvent],
        ttps: List[TTP],
        anomalies: Dict
    ) -> str:
        """Convert markdown report to HTML with Chart.js visualizations"""
        
        # Prepare chart data
        chart_data = self._prepare_chart_data(events, ttps)
        
        # Simple markdown-to-HTML conversion
        import markdown
        
        html_body = markdown.markdown(
            report_md,
            extensions=['tables', 'fenced_code', 'nl2br']
        )
        
        # Wrap in professional HTML template with Chart.js
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>One_Blink - SOC Intelligence Report</title>
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }}
        h3 {{
            color: #555;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        table th, table td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        table th {{
            background: #3498db;
            color: white;
        }}
        table tr:nth-child(even) {{
            background: #f9f9f9;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .verdict-malicious {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .verdict-suspicious {{
            color: #f39c12;
            font-weight: bold;
        }}
        .verdict-benign {{
            color: #27ae60;
            font-weight: bold;
        }}
        .confidence-high {{
            color: #27ae60;
        }}
        .confidence-medium {{
            color: #f39c12;
        }}
        .confidence-low {{
            color: #e74c3c;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 2rem;
            margin: 2rem 0;
        }}
        .chart-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 0.5rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .chart-canvas {{
            position: relative;
            height: 300px;
            margin-top: 1rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Report Header -->
        <h1 style="color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px;">
            &#9672; One_Blink Forensics Report
        </h1>
        <p style="color: #7f8c8d;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <!-- Charts Section -->
        <div class="charts-grid">
            <div class="chart-card">
                <h3>Traffic Volume Over Time</h3>
                <div class="chart-canvas"><canvas id="trafficChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>Protocol Distribution</h3>
                <div class="chart-canvas"><canvas id="protocolChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>Risk Timeline</h3>
                <div class="chart-canvas"><canvas id="riskChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>Top Talkers</h3>
                <div class="chart-canvas"><canvas id="talkersChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>Connection States</h3>
                <div class="chart-canvas"><canvas id="statesChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>MITRE ATT&CK Coverage</h3>
                <div class="chart-canvas"><canvas id="mitreChart"></canvas></div>
            </div>
        </div>
        
        <!-- Report Content -->
        {html_body}
        
        <div class="footer">
            <p>Generated by One_Blink - SOC Intelligence Ultimate Analysis Engine v1.0</p>
            <p>Timestamp: {datetime.now().isoformat()}</p>
            <p>Total Events Analyzed: {len(events)}</p>
            <p>TTPs Detected: {len(ttps)}</p>
            <p>Anomalies Found: {anomalies.get('total_anomalies', 0)}</p>
        </div>
    </div>
    
    <!-- Chart.js Rendering -->
    <script>
        const chartData = {json.dumps(chart_data)};
        
        // Chart 1: Traffic Volume
        new Chart(document.getElementById('trafficChart'), {{
            type: 'line',
            data: {{
                labels: chartData.traffic_volume.labels,
                datasets: [{{
                    label: 'Traffic (MB)',
                    data: chartData.traffic_volume.volumes,
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    fill: true,
                    tension: 0.4
                }}]
            }},
            options: {{ responsive: true, maintainAspectRatio: false }}
        }});
        
        // Chart 2: Protocol Distribution
        new Chart(document.getElementById('protocolChart'), {{
            type: 'doughnut',
            data: {{
                labels: chartData.protocol_distribution.protocols,
                datasets: [{{
                    data: chartData.protocol_distribution.counts,
                    backgroundColor: ['#3498db', '#9b59b6', '#1abc9c', '#f39c12', '#e74c3c']
                }}]
            }},
            options: {{ responsive: true, maintainAspectRatio: false }}
        }});
        
        // Chart 3: Risk Timeline
        new Chart(document.getElementById('riskChart'), {{
            type: 'bar',
            data: {{
                labels: chartData.risk_timeline.time_buckets,
                datasets: [
                    {{ label: 'High Risk', data: chartData.risk_timeline.high_risk, backgroundColor: '#e74c3c' }},
                    {{ label: 'Suspicious', data: chartData.risk_timeline.suspicious, backgroundColor: '#f39c12' }},
                    {{ label: 'Normal', data: chartData.risk_timeline.normal, backgroundColor: '#2ecc71' }}
                ]
            }},
            options: {{ responsive: true, maintainAspectRatio: false, scales: {{ x: {{ stacked: true }}, y: {{ stacked: true }} }} }}
        }});
        
        // Chart 4: Top Talkers
        new Chart(document.getElementById('talkersChart'), {{
            type: 'bar',
            data: {{
                labels: chartData.top_talkers.ips,
                datasets: [{{
                    label: 'Packets',
                    data: chartData.top_talkers.packet_counts,
                    backgroundColor: '#3498db'
                }}]
            }},
            options: {{ indexAxis: 'y', responsive: true, maintainAspectRatio: false }}
        }});
        
        // Chart 5: Connection States
        new Chart(document.getElementById('statesChart'), {{
            type: 'polarArea',
            data: {{
                labels: chartData.connection_states.states,
                datasets: [{{
                    data: chartData.connection_states.counts,
                    backgroundColor: ['rgba(52,152,219,0.7)', 'rgba(155,89,182,0.7)', 'rgba(26,188,156,0.7)', 'rgba(243,156,18,0.7)', 'rgba(231,76,60,0.7)']
                }}]
            }},
            options: {{ responsive: true, maintainAspectRatio: false }}
        }});
        
        // Chart 6: MITRE Heatmap
        new Chart(document.getElementById('mitreChart'), {{
            type: 'bar',
            data: {{
                labels: chartData.mitre_heatmap.tactics,
                datasets: [{{
                    label: 'Techniques',
                    data: chartData.mitre_heatmap.technique_counts,
                    backgroundColor: '#e74c3c'
                }}]
            }},
            options: {{ responsive: true, maintainAspectRatio: false }}
        }});
    </script>
</body>
</html>
"""
        
        return html
    
    def _convert_to_json(
        self,
        report_md: str,
        events: List[TOONEvent],
        ttps: List[TTP],
        anomalies: Dict,
        historical_stats: Optional[Dict]
    ) -> str:
        """Convert report to JSON (for SIEM/SOAR integration)"""
        
        output = {
            "report_id": f"RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "analyst_engine": "SOC_Intelligence Ultimate v1.0",
            "markdown_report": report_md,
            "summary": {
                "total_events": len(events),
                "ttps_detected": len(ttps),
                "anomalies_found": anomalies.get('total_anomalies', 0)
            },
            "ttps": [
                {
                    "technique_id": ttp.technique_id,
                    "technique_name": ttp.technique_name,
                    "tactic": ttp.tactic,
                    "confidence": ttp.confidence,
                    "evidence": ttp.evidence
                }
                for ttp in ttps
            ],
            "anomalies": anomalies,
            "historical_stats": historical_stats,
            "events_sample": [
                {
                    "timestamp": e.t,
                    "src": e.si,
                    "dst": e.di,
                    "protocol": e.pr,
                    "details": {
                        "dns_query": e.dns_query,
                        "http_host": e.http_host,
                        "tls_sni": e.tls_sni
                    }
                }
                for e in events[:20]  # First 20 events
            ]
        }
        
        return json.dumps(output, indent=2)
    
    def save_report(
        self,
        report_content: str,
        output_path: Path,
        format: str = "html"
    ) -> Path:
        """
        Save report to file
        
        Args:
            report_content: Generated report string
            output_path: Where to save
            format: File format
        
        Returns:
            Path to saved report
        """
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        logger.info(f"Report saved: {output_path}")
        return output_path
