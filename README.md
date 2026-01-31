# SOC_Intelligence

**Unified Network Security Operations Platform**

Combines the best of One_Blink (Interactive PCAP Analysis) and SecAI Reporter (Automated SOC Reporting) into a comprehensive security operations platform.

## Overview

SOC_Intelligence is an integrated platform that provides:
- Real-time PCAP analysis and visualization
- Automated SOC ticket report generation
- MITRE ATT&CK technique mapping
- Historical correlation analysis
- AI-powered insights and conclusions
- Both GUI (Streamlit) and CLI interfaces

## Features

### From One_Blink
- ✅ Deep PCAP analysis (TShark, Zeek, Snort)
- ✅ Interactive dashboards and visualizations
- ✅ Real-time threat detection
- ✅ DuckDB for fast local storage

### From SecAI Reporter
- ✅ Professional HTML/JSON report generation
- ✅ MITRE ATT&CK technique inference
- ✅ Historical correlation (75/25 weighting)
- ✅ Enterprise integration (PostgreSQL, Impala)
- ✅ Air-gapped deployment support

### New Unified Capabilities
- ✅ PCAP → Professional Report workflow
- ✅ Combined analysis engine
- ✅ Unified data schema
- ✅ Multi-source ingestion

## Quick Start

### Installation

```bash
# Clone repository
cd /opt
git clone <repo-url> SOC_Intelligence
cd SOC_Intelligence

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### GUI Mode (Streamlit)

```bash
streamlit run src/app/main.py
```

Access at: http://localhost:8501

### CLI Mode

```bash
# Analyze PCAP file
python -m src.cli analyze --pcap sample.pcap --output report.html

# Generate ticket report
python -m src.cli report --ticket-id 12345 --output-dir ./reports
```

## Architecture

```
Input Layer          Analysis Layer        Output Layer
┌──────────┐         ┌──────────┐         ┌──────────┐
│  PCAP    │────────▶│  TShark  │────────▶│Dashboard │
│  Files   │         │  Zeek    │         │  GUI     │
└──────────┘         │  Snort   │         └──────────┘
                     └──────────┘              │
┌──────────┐              │                    ▼
│PostgreSQL│────────▶┌────▼─────┐         ┌──────────┐
│ Tickets  │         │  Unified │────────▶│  HTML    │
└──────────┘         │  Analysis│         │  Report  │
                     │  Engine  │         └──────────┘
┌──────────┐         │          │              │
│  Zeek    │────────▶│ • MITRE  │              ▼
│  Logs    │         │ • AI/LLM │         ┌──────────┐
└──────────┘         │ • Correl.│         │   PDF    │
                     └──────────┘         └──────────┘
```

## Project Structure

```
SOC_Intelligence/
├── src/
│   ├── unified/              # Core unified components
│   │   ├── models/          # Pydantic data models
│   │   ├── db/              # Database adapters (DuckDB, PostgreSQL, Impala)
│   │   ├── ingestion/       # Data ingestion pipelines
│   │   ├── analysis/        # Analysis engines (TTP, Historical, AI)
│   │   ├── reports/         # Report generation
│   │   └── ai/              # AI/LLM services
│   │
│   ├── app/                 # Streamlit GUI
│   │   ├── pages/           # Multi-page app
│   │   └── components/      # UI components
│   │
│   ├── charts/              # Visualization components
│   ├── cli/                 # Command-line interface
│   └── utils/               # Shared utilities
│
├── templates/               # Jinja2 templates for reports
├── config/                  # Configuration files
├── schemas/                 # JSON schemas
├── tests/                   # Test suite
├── scripts/                 # Utility scripts
├── docs/                    # Documentation
├── data/                    # Local data storage
└── logs/                    # Application logs
```

## Configuration

### Environment Setup

Copy `.env.example` to `.env` and configure:

```bash
# Database
DUCKDB_PATH=./data/soc_intelligence.duckdb
POSTGRESQL_HOST=localhost
POSTGRESQL_PORT=5432
IMPALA_HOST=impala-host
IMPALA_PORT=21050

# Analysis
ENABLE_ZEEK=true
ENABLE_SNORT=true
ENABLE_LLM=false  # Set to true for AI features

# Report Generation
DEFAULT_TEMPLATE=standard
OUTPUT_FORMAT=html,json
```

## Documentation

- [Integration Plan](docs/integration_plan.md) - Full integration roadmap
- [Capabilities Analysis](docs/capabilities_analysis.md) - Detailed feature comparison
- [API Reference](docs/api_reference.md) - API documentation
- [User Guide](docs/user_guide.md) - Complete usage guide

## Development Status

**Current Phase**: Phase 1 - Unified Data Layer

See [task.md](task.md) for detailed progress.

## Contributing

This is an internal project. See development guidelines in `docs/development.md`.

## License

Internal Use Only

## Credits

- **One_Blink**: Network forensics and visualization
- **SecAI Reporter**: Automated report generation and MITRE mapping
- **Integration**: SOC_Intelligence Team
