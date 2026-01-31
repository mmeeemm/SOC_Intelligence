"""
SecAI Reporter CLI

Command-line interface for generating SOC ticket reports.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import yaml


def setup_logging(level: str = 'INFO', log_file: Optional[str] = None):
    """Configure logging."""
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file."""
    # Handle environment variable substitution
    import re
    
    with open(config_path, 'r') as f:
        content = f.read()
    
    # Replace ${VAR:default} patterns
    def replace_env(match):
        var_expr = match.group(1)
        if ':' in var_expr:
            var_name, default = var_expr.split(':', 1)
        else:
            var_name = var_expr
            default = ''
        return os.environ.get(var_name, default)
    
    content = re.sub(r'\$\{([^}]+)\}', replace_env, content)
    
    return yaml.safe_load(content)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='SecAI Reporter - Air-Gapped SOC Ticket Web Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Generate report for ticket ID 12345:
    python -m secai_reporter.cli --ticket-id 12345

  With custom config and output directory:
    python -m secai_reporter.cli --ticket-id 12345 --config /etc/secai/config.yaml --output-dir ./reports

  Dry run (validate without database connections):
    python -m secai_reporter.cli --ticket-id 12345 --dry-run
        """
    )
    
    parser.add_argument(
        '--ticket-id', '-t',
        required=True,
        help='Ticket ID to generate report for'
    )
    
    parser.add_argument(
        '--config', '-c',
        default=None,
        help='Path to config.yaml (default: ./config/config.yaml)'
    )
    
    parser.add_argument(
        '--output-dir', '-o',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )
    
    parser.add_argument(
        '--log-level', '-l',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--log-file',
        default=None,
        help='Optional log file path'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Validate configuration without connecting to databases'
    )
    
    parser.add_argument(
        '--skip-llm',
        action='store_true',
        help='Skip LLM inference, use template fallback only'
    )
    
    parser.add_argument(
        '--validate-only',
        action='store_true',
        help='Only validate an existing JSON report against schema'
    )
    
    parser.add_argument(
        '--json-file',
        default=None,
        help='JSON file to validate (use with --validate-only)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level, args.log_file)
    logger = logging.getLogger('secai_reporter')
    
    # Find project root
    project_root = Path(__file__).parent.parent.parent
    
    # Determine config path
    if args.config:
        config_path = Path(args.config)
    else:
        config_path = project_root / 'config' / 'config.yaml'
    
    if not config_path.exists():
        logger.error(f"Configuration file not found: {config_path}")
        sys.exit(1)
    
    # Load config
    try:
        config = load_config(str(config_path))
        logger.info(f"Loaded configuration from {config_path}")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Handle validate-only mode
    if args.validate_only:
        if not args.json_file:
            logger.error("--json-file is required with --validate-only")
            sys.exit(1)
        
        from .report.render import ReportRenderer
        import json
        import jsonschema
        
        schema_path = project_root / 'schemas' / 'ticket_web_report.schema.json'
        
        try:
            with open(schema_path, 'r') as f:
                schema = json.load(f)
            
            with open(args.json_file, 'r') as f:
                data = json.load(f)
            
            jsonschema.validate(instance=data, schema=schema)
            logger.info(f"✅ JSON validation passed: {args.json_file}")
            sys.exit(0)
        except jsonschema.ValidationError as e:
            logger.error(f"❌ JSON validation failed: {e.message}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error: {e}")
            sys.exit(1)
    
    # Handle dry-run mode
    if args.dry_run:
        logger.info("Dry run mode - validating configuration only")
        
        # Check required config sections
        required_sections = ['postgresql', 'impala']
        missing = [s for s in required_sections if s not in config]
        
        if missing:
            logger.error(f"Missing required config sections: {missing}")
            sys.exit(1)
        
        # Check schema and template exist
        schema_path = project_root / 'schemas' / 'ticket_web_report.schema.json'
        template_path = project_root / 'templates' / 'report.html.j2'
        
        if not schema_path.exists():
            logger.warning(f"Schema file not found: {schema_path}")
        else:
            logger.info(f"✅ Schema file found: {schema_path}")
        
        if not template_path.exists():
            logger.warning(f"Template file not found: {template_path}")
        else:
            logger.info(f"✅ Template file found: {template_path}")
        
        logger.info("✅ Configuration validation passed")
        sys.exit(0)
    
    # Modify config based on flags
    if args.skip_llm:
        config.setdefault('llm', {})['model_path'] = None
        config['llm']['fallback_to_template'] = True
        logger.info("LLM inference disabled, using template fallback")
    
    # Generate report
    try:
        from .report import generate_report
        
        logger.info(f"Generating report for ticket: {args.ticket_id}")
        
        json_path, html_path = generate_report(
            args.ticket_id,
            config,
            args.output_dir
        )
        
        logger.info(f"✅ Report generated successfully!")
        logger.info(f"   JSON: {json_path}")
        if html_path:
            logger.info(f"   HTML: {html_path}")
        
    except ValueError as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Failed to generate report: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
