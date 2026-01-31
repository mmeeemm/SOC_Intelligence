"""
Report Renderer

Generates JSON and HTML reports from aggregated data.
Validates JSON against schema before output.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

import jsonschema
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import TicketReport

logger = logging.getLogger(__name__)


class ReportRenderer:
    """
    Renders ticket reports as JSON and HTML.
    
    Validates JSON against schema and uses Jinja2 for HTML.
    """
    
    def __init__(self, config: Dict[str, Any], schema_path: Optional[str] = None,
                 template_dir: Optional[str] = None):
        """
        Initialize renderer.
        
        Args:
            config: Output configuration
            schema_path: Path to JSON schema file
            template_dir: Directory containing HTML templates
        """
        self.config = config
        self.schema_version = config.get('schema_version', '1.0.0')
        self.json_indent = config.get('json_indent', 2)
        
        # Load JSON schema
        self.schema = None
        if schema_path and os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                self.schema = json.load(f)
        
        # Setup Jinja2
        if template_dir and os.path.exists(template_dir):
            self.jinja_env = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            self.jinja_env = None
    
    def build_report(self, ticket_data: Dict[str, Any],
                     aggregates: Dict[str, Any],
                     historical_stats: Dict[str, Any],
                     ttps: list,
                     ai_generated: Dict[str, Any],
                     t0: datetime,
                     window_hours: int = 24) -> TicketReport:
        """
        Build a complete TicketReport from components.
        
        Args:
            ticket_data: Ticket information
            aggregates: Zeek aggregates
            historical_stats: Historical statistics
            ttps: Detected TTPs
            ai_generated: AI-generated analysis
            t0: Anchor timestamp
            window_hours: Analysis window hours
            
        Returns:
            TicketReport model instance
        """
        from .models import (
            TicketInfo, TriggerInfo, AnalysisWindow, IndicatorInfo,
            HistoricalStats as HistoricalStatsModel, CurrentWindowSummary,
            AIGenerated, Confidence, RecommendedActions, ObservedTTP,
            ZeekFieldReview, AdditionalAssets, PeerSummary
        )
        
        # Build ticket info
        trigger = TriggerInfo(
            type=ticket_data.get('trigger_type', 'ioc_match'),
            value=ticket_data.get('trigger_value', ''),
            timestamp=t0
        )
        
        ticket = TicketInfo(
            id=str(ticket_data.get('id', '')),
            created_at=ticket_data.get('created_at', datetime.utcnow()),
            status=ticket_data.get('status', 'open'),
            severity=ticket_data.get('severity', 'medium'),
            outcome=ticket_data.get('outcome', 'Unset'),
            trigger=trigger,
            data_sources=['PostgreSQL', 'Impala/Zeek']
        )
        
        # Build analysis window
        window = AnalysisWindow(
            anchor_t0=t0,
            start=t0 - timedelta(hours=window_hours),
            end=t0 + timedelta(hours=window_hours),
            duration_hours=window_hours * 2
        )
        
        # Build indicator
        current_summary = aggregates.get('current_window_summary', {})
        indicator = IndicatorInfo(
            ioc_type=ticket_data.get('trigger_type', 'domain').replace('_match', ''),
            ioc_value=ticket_data.get('trigger_value', ''),
            matched_fields=list(current_summary.get('sightings_by_matched_field', {}).keys()),
            protocols_involved=[p.get('protocol', '') for p in current_summary.get('protocol_coverage', [])],
            first_seen_in_window=aggregates.get('first_seen'),
            last_seen_in_window=aggregates.get('last_seen')
        )
        
        # Build historical stats
        hist = HistoricalStatsModel(
            total_tickets=historical_stats.get('total_tickets', 0),
            threat_count=historical_stats.get('threat_count', 0),
            false_positive_count=historical_stats.get('false_positive_count', 0),
            threat_ratio=historical_stats.get('threat_ratio'),
            last_observed_ticket=historical_stats.get('last_observed_ticket')
        )
        
        # Build current window summary
        peer_data = current_summary.get('peer_entity_summary', {})
        peer_summary = PeerSummary(
            top_peers=[],
            top1_share=peer_data.get('top1_share', 0.0),
            top3_share=peer_data.get('top3_share', 0.0)
        )
        
        current = CurrentWindowSummary(
            total_ioc_sightings=current_summary.get('total_ioc_sightings', 0),
            distinct_src_ip_count=current_summary.get('distinct_src_ip_count', 0),
            distinct_dst_ip_count=current_summary.get('distinct_dst_ip_count', 0),
            distinct_country_pairs=current_summary.get('distinct_country_pairs', 0),
            protocol_coverage=current_summary.get('protocol_coverage', []),
            sightings_by_log_type=current_summary.get('sightings_by_log_type', {}),
            sightings_by_matched_field=current_summary.get('sightings_by_matched_field', {}),
            country_pair_distribution=current_summary.get('country_pair_distribution', []),
            peer_entity_summary=peer_summary,
            temporal_distribution=current_summary.get('temporal_distribution', []),
            protocol_specific_details=current_summary.get('protocol_specific_details', {})
        )
        
        # Build field review
        field_review = ZeekFieldReview(
            fields_present=aggregates.get('zeek_field_review', {}).get('fields_present', {}),
            fields_used_in_summary=aggregates.get('zeek_field_review', {}).get('fields_used_in_summary', {})
        )
        
        # Build additional assets
        assets_data = aggregates.get('additional_assets_involved', {})
        assets = AdditionalAssets(
            distinct_ip_total=assets_data.get('distinct_ip_total', 0),
            distinct_ip_excluding_trigger=assets_data.get('distinct_ip_excluding_trigger', 0),
            nat_aggregation_note=assets_data.get('nat_aggregation_note', '')
        )
        
        # Build TTPs
        observed_ttps = [
            ObservedTTP(
                technique_id=t.get('technique_id', ''),
                technique_name=t.get('technique_name', ''),
                justification=t.get('justification', ''),
                confidence=t.get('confidence', 0.0)
            )
            for t in ttps
        ]
        
        # Build AI generated
        ai = AIGenerated(
            detailed_communications_analysis=ai_generated.get('detailed_communications_analysis', ''),
            technical_conclusion=ai_generated.get('technical_conclusion', ''),
            confidence=Confidence(
                level=ai_generated.get('confidence', {}).get('level', 'medium'),
                score=ai_generated.get('confidence', {}).get('score', 0.5)
            )
        )
        
        # Build recommended actions
        actions = self._generate_recommended_actions(current, hist, ai.confidence.level)
        
        # Create report
        report = TicketReport(
            schema_version=self.schema_version,
            generated_at=datetime.utcnow(),
            ticket=ticket,
            analysis_window=window,
            indicator=indicator,
            historical_ticket_statistics=hist,
            current_window_summary=current,
            additional_assets_involved=assets,
            zeek_field_review=field_review,
            observed_ttps=observed_ttps,
            ai_generated=ai,
            recommended_actions=actions
        )
        
        return report
    
    def _generate_recommended_actions(self, current: Any, 
                                       historical: Any,
                                       confidence: str) -> 'RecommendedActions':
        """Generate recommended actions based on analysis."""
        from .models import RecommendedActions
        
        immediate = []
        validation = []
        long_term = []
        
        # High confidence threat
        if confidence == 'high':
            immediate.extend([
                "Block the IOC at perimeter firewall/proxy",
                "Isolate affected assets for forensic analysis",
                "Notify incident response team"
            ])
        elif confidence == 'medium':
            immediate.extend([
                "Add IOC to monitoring watchlist",
                "Increase logging for involved assets"
            ])
        
        # Validation steps
        validation.extend([
            "Correlate with endpoint detection logs",
            "Check for related IOCs in threat intelligence feeds",
            "Validate business justification for observed traffic"
        ])
        
        # Long-term
        if historical.threat_ratio and historical.threat_ratio > 0.5:
            long_term.append("Update IOC reputation in threat intel platform")
        
        long_term.extend([
            "Document findings in case management system",
            "Update detection rules if new patterns identified"
        ])
        
        return RecommendedActions(
            immediate=immediate,
            validation=validation,
            long_term=long_term
        )
    
    def render_json(self, report: TicketReport, validate: bool = True) -> str:
        """
        Render report as JSON string.
        
        Args:
            report: TicketReport instance
            validate: Whether to validate against schema
            
        Returns:
            JSON string
        """
        data = report.model_dump(mode='json')
        
        if validate and self.schema:
            try:
                jsonschema.validate(instance=data, schema=self.schema)
                logger.info("JSON validation passed")
            except jsonschema.ValidationError as e:
                logger.error(f"JSON validation failed: {e.message}")
                raise
        
        return json.dumps(data, indent=self.json_indent, ensure_ascii=False)
    
    def render_html(self, report: TicketReport, template_name: str = 'report.html.j2') -> str:
        """
        Render report as HTML.
        
        Args:
            report: TicketReport instance
            template_name: Jinja2 template filename
            
        Returns:
            HTML string
        """
        if not self.jinja_env:
            raise RuntimeError("Jinja2 environment not configured")
        
        template = self.jinja_env.get_template(template_name)
        return template.render(report=report, generated_at=datetime.utcnow())
    
    def save_report(self, report: TicketReport, output_dir: str,
                    validate: bool = True) -> tuple:
        """
        Save report as JSON and HTML files.
        
        Args:
            report: TicketReport instance
            output_dir: Output directory
            validate: Whether to validate JSON
            
        Returns:
            Tuple of (json_path, html_path)
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        ticket_id = report.ticket.id
        json_path = output_path / f"ticket_{ticket_id}.json"
        html_path = output_path / f"ticket_{ticket_id}.html"
        
        # Save JSON
        json_content = self.render_json(report, validate=validate)
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(json_content)
        logger.info(f"Saved JSON report: {json_path}")
        
        # Save HTML
        if self.jinja_env:
            html_content = self.render_html(report)
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"Saved HTML report: {html_path}")
        else:
            html_path = None
            logger.warning("HTML template not configured, skipping HTML output")
        
        return str(json_path), str(html_path) if html_path else None


def generate_report(ticket_id: str, config: Dict[str, Any],
                    output_dir: str) -> tuple:
    """
    High-level function to generate a complete report.
    
    This is the main entry point for report generation.
    
    Args:
        ticket_id: Ticket identifier
        config: Full configuration dictionary
        output_dir: Output directory for reports
        
    Returns:
        Tuple of (json_path, html_path)
    """
    from ..connectors import PostgresDjangoConnector, ImpalaConnector
    from ..aggregation import aggregate_zeek_data, compute_historical_stats
    from ..ttp_mapping import map_ttps
    from ..llm import generate_ai_analysis
    
    # Get paths
    project_root = Path(__file__).parent.parent.parent.parent
    schema_path = project_root / 'schemas' / 'ticket_web_report.schema.json'
    template_dir = project_root / 'templates'
    
    # Initialize renderer
    renderer = ReportRenderer(
        config.get('output', {}),
        schema_path=str(schema_path) if schema_path.exists() else None,
        template_dir=str(template_dir) if template_dir.exists() else None
    )
    
    # Fetch ticket data
    with PostgresDjangoConnector(config.get('postgresql', {})) as pg:
        ticket = pg.get_ticket(ticket_id)
        if not ticket:
            raise ValueError(f"Ticket {ticket_id} not found")
        
        ticket_data = {
            'id': ticket.id,
            'created_at': ticket.created_at,
            'status': ticket.status,
            'severity': ticket.severity,
            'outcome': ticket.outcome,
            'trigger_type': ticket.trigger_type,
            'trigger_value': ticket.trigger_value
        }
        t0 = ticket.trigger_timestamp
        
        # Get historical stats
        hist_raw = pg.get_historical_stats(
            ticket.trigger_type, 
            ticket.trigger_value,
            exclude_ticket_id=ticket_id
        )
        historical_stats = compute_historical_stats(hist_raw)
    
    # Query Zeek logs
    window_hours = config.get('analysis', {}).get('window_hours', 24)
    bucket_minutes = config.get('analysis', {}).get('temporal_bucket_minutes', 15)
    
    with ImpalaConnector(config.get('impala', {})) as impala:
        zeek_raw = impala.query_zeek_aggregates(
            ticket.trigger_type,
            ticket.trigger_value,
            t0,
            window_hours=window_hours,
            bucket_minutes=bucket_minutes
        )
        aggregates = aggregate_zeek_data(zeek_raw)
    
    # Map TTPs
    ttps = map_ttps(
        aggregates.get('current_window_summary', {}),
        historical_stats
    )
    
    # Generate AI analysis
    ai_generated = generate_ai_analysis(
        aggregates.get('current_window_summary', {}),
        historical_stats,
        ttps,
        ticket_data,
        config.get('llm', {})
    )
    
    # Build report
    report = renderer.build_report(
        ticket_data,
        aggregates,
        historical_stats,
        ttps,
        ai_generated,
        t0,
        window_hours
    )
    
    # Save report
    return renderer.save_report(report, output_dir)
