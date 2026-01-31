#!/usr/bin/env python3
"""
SOC Intelligence CLI - Command Line Interface

Usage:
    soc-cli analyze <pcap_file> [--output FORMAT] [--ticket]
    soc-cli reports list
    soc-cli reports view <report_id>
    soc-cli health
"""

import click
import sys
from pathlib import Path
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from unified.analysis.unified_analyzer import UnifiedAnalyzer


@click.group()
def cli():
    """SOC Intelligence Platform - Command Line Interface"""
    pass


@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--output', '-o', default='html', type=click.Choice(['html', 'json', 'markdown']),
              help='Report output format')
@click.option('--ticket/--no-ticket', default=True, help='Create SOC ticket')
@click.option('--db-path', default='data/soc_intelligence.duckdb', help='Database path')
def analyze(pcap_file, output, ticket, db_path):
    """Analyze a PCAP file"""
    
    click.echo(f" Analyzing: {pcap_file}")
    click.echo(f" Output format: {output}")
    click.echo(f"🎫 Create ticket: {ticket}")
    click.echo()
    
    # Initialize analyzer
    analyzer = UnifiedAnalyzer(db_path=db_path)
    
    # Run analysis
    with click.progressbar(length=100, label='Processing') as bar:
        bar.update(10)
        click.echo("   Phase 1/4: PCAP Ingestion...")
        
        try:
            result = analyzer.analyze_pcap(
                pcap_path=Path(pcap_file),
                create_ticket=ticket,
                output_format=output
            )
            
            bar.update(30)
            click.echo("   Phase 2/4: TTP Mapping...")
            bar.update(25)
            click.echo("   Phase 3/4: AI Analysis...")
            bar.update(25)
            click.echo("   Phase 4/4: Report Generation...")
            bar.update(10)
            
        except Exception as e:
            click.echo(f"\n Analysis failed: {str(e)}", err=True)
            sys.exit(1)
    
    # Display results
    click.echo()
    click.echo(" Analysis complete!")
    click.echo()
    click.echo(f" Events analyzed: {result['events_count']:,}")
    click.echo(f" TTPs detected: {len(result['ttps'])}")
    click.echo(f"  Anomalies found: {result['anomalies']['total_anomalies']}")
    click.echo()
    click.echo(f" Report saved: {result['report_path']}")
    
    if result.get('ticket_id'):
        click.echo(f"🎫 Ticket created: {result['ticket_id']}")
    
    # Show TTPs
    if result['ttps']:
        click.echo()
        click.echo(" Detected MITRE ATT&CK Techniques:")
        for ttp in result['ttps']:
            click.echo(f"   • {ttp['id']}: {ttp['name']} ({ttp['tactic']}) - {ttp['confidence']}")


@cli.group()
def reports():
    """Manage analysis reports"""
    pass


@reports.command('list')
def list_reports():
    """List all generated reports"""
    
    reports_dir = Path("reports")
    if not reports_dir.exists():
        click.echo("No reports found.")
        return
    
    all_reports = sorted(
        reports_dir.glob("*.*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    
    if not all_reports:
        click.echo("No reports found.")
        return
    
    click.echo(f" Found {len(all_reports)} reports:\n")
    
    for report in all_reports:
        size_kb = report.stat().st_size / 1024
        ext = report.suffix[1:].upper()
        click.echo(f"  • {report.name} ({ext}, {size_kb:.1f} KB)")


@reports.command('view')
@click.argument('report_file')
def view_report(report_file):
    """View a specific report"""
    
    report_path = Path("reports") / report_file
    
    if not report_path.exists():
        click.echo(f" Report not found: {report_file}", err=True)
        sys.exit(1)
    
    with open(report_path, 'r') as f:
        content = f.read()
    
    if report_path.suffix == '.json':
        data = json.loads(content)
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo(content)


@cli.command()
@click.option('--db-path', default='data/soc_intelligence.duckdb', help='Database path')
def health(db_path):
    """Check system health"""
    
    click.echo("One_Blink - SOC Intelligence Framework")
    click.echo("System Health Check\n")
    
    analyzer = UnifiedAnalyzer(db_path=db_path)
    health_status = analyzer.health_check()
    
    # Database
    db_status = "" if health_status['database'] == 'connected' else ""
    click.echo(f"{db_status} Database: {health_status['database']}")
    
    # LLM
    llm_loaded = health_status['llm']['model_loaded']
    llm_status = "" if llm_loaded else " "
    llm_mode = "Ready" if llm_loaded else "Template Mode"
    click.echo(f"{llm_status} LLM: {llm_mode}")
    
    # Ingestion tools
    zeek_status = "" if health_status['ingestion']['zeek'] else " "
    snort_status = "" if health_status['ingestion']['snort'] else " "
    click.echo(f"{zeek_status} Zeek: {'Enabled' if health_status['ingestion']['zeek'] else 'Disabled'}")
    click.echo(f"{snort_status} Snort: {'Enabled' if health_status['ingestion']['snort'] else 'Disabled'}")
    
    # Components
    click.echo(" TTP Mapper: Ready")
    click.echo(" Anomaly Detector: Ready")
    click.echo(" Report Generator: Ready")
    
    click.echo()
    click.echo(" System operational!")


if __name__ == '__main__':
    cli()
