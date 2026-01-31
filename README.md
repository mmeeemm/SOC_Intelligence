# One_Blink

**SOC Intelligence Framework - Enterprise Cybersecurity Analysis Platform**

Unified platform combining advanced network forensics, AI-powered threat intelligence, and professional SOC reporting.

---

##  Overview

SOC_Intelligence is a comprehensive network security analysis platform that provides:

- **Live PCAP Analysis**: Real-time network traffic forensics with TShark/PyShark
- **Professional SOC Reports**: Enterprise-grade 14-section analysis following industry standards
- **AI-Powered Intelligence**: Local LLM with Ultimate Prompt for deterministic, evidence-based analysis
- **Historical Correlation**: 75/25 weighted threat assessment using historical data
- **MITRE ATT&CK Mapping**: Automatic technique identification with confidence scoring
- **ML Anomaly Detection**: Beaconing, DNS tunneling, port scanning detection
- **Air-Gapped Ready**: Full CPU-only operation for secure environments

---

##  Key Features

###  **Analysis Capabilities**
- TOON-normalized data processing (L3+ only, no inference)
- PyShark/TShark optimized ingestion
- Zeek enrichment support
- Snort IDS integration
- Pattern recognition (beaconing, tunneling, scanning)
- Statistical baseline analysis

###  **Reporting**
- 14-section enterprise report structure
- HTML, JSON, and Markdown output formats
- Professional templates with visualizations
- Evidence citations and confidence scoring
- Executive summaries + technical deep dives

###  **AI Integration**
- Local LLM (CPU-only, air-gapped compatible)
- Ultimate Prompt system for consistent analysis
- Vision AI for screenshot/artifact analysis
- Template fallback for offline operation

###  **User Interfaces**
- **Streamlit Dashboard**: Interactive web UI
- **CLI Tool**: Command-line interface for automation
- **API Ready**: FastAPI integration (planned)

---

##  Quick Start

### Installation

```bash
# Clone the repository
git clone <repository_url>
cd SOC_Intelligence

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Dashboard

```bash
# Launch Streamlit UI
./run_dashboard.sh

# Or manually:
streamlit run src/app/main.py
```

Access at: `http://localhost:8501`

### Using the CLI

```bash
# Analyze a PCAP file
python src/cli/soc_cli.py analyze sample.pcap --output html

# List reports
python src/cli/soc_cli.py reports list

# Check system health
python src/cli/soc_cli.py health
```

---

##  Project Structure

```
SOC_Intelligence/
├── src/
│   ├── unified/           # Core unified components
│   │   ├── models/        # Data schemas (TOON, Ticket, Report)
│   │   ├── db/            # Database adapters (DuckDB, Impala)
│   │   ├── ingestion/     # PCAP ingestion engine
│   │   ├── ai/            # LLM, Vision AI, Ultimate Prompt
│   │   ├── analysis/      # TTP Mapper, Anomaly Detector, Unified Analyzer
│   │   └── reports/       # Report generator
│   ├── app/               # Streamlit UI
│   │   ├── main.py        # Main dashboard
│   │   └── pages/         # UI pages
│   └── cli/               # Command-line interface
├── data/                  # Database files
├── reports/               # Generated reports
├── uploads/               # Uploaded PCAP files
├── tests/                 # Validation tests
├── templates/             # Report templates (from SecAI)
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

---

##  Configuration

### Database
- **DuckDB**: Local fast storage (`data/soc_intelligence.duckdb`)
- **Impala**: Optional Zeek logs connector (configure in `.env`)

### LLM Model
```python
# In code or via environment variable
LLM_MODEL_PATH = "/path/to/mistral-7b-instruct"  # Optional
```

If no model path provided, the system uses template-based fallback.

### Environment Variables
Copy `.env.example` to `.env` and configure:
```bash
# Database
DUCKDB_PATH=data/soc_intelligence.duckdb

# LLM (optional)
LLM_MODEL_PATH=/path/to/model
LLM_DEVICE=cpu  # or cuda

# Tools
ZEEK_ENABLED=true
SNORT_ENABLED=true
```

---

##  Workflow

```
PCAP File
    ↓
[1] Ingestion (TShark → TOON normalization)
    ↓
[2] Enrichment (Zeek logs, Snort alerts)
    ↓
[3] Analysis (TTPs, Anomalies, Patterns)
    ↓
[4] Historical Correlation (75/25 weighting)
    ↓
[5] AI Analysis (Ultimate Prompt → LLM)
    ↓
[6] Report Generation (14-section enterprise report)
    ↓
HTML/JSON/MD Report + SOC Ticket
```

---

##  Testing

```bash
# Run validation tests
pytest tests/ -v

# Test specific component
pytest tests/test_core.py::test_ttp_mapper -v
```

---

## 📖 Documentation

### Ultimate Prompt
The analysis engine follows the [Ultimate SOC Intelligence Prompt](src/unified/ai/ultimate_prompt.py) specification:

- **Authoritative Rules**: Evidence-based only, no inference
- **Input Contract**: TOON data, historical context, MITRE TTPs
- **Output Structure**: 14 sections (Executive Verdict → Confidence Statement)
- **75/25 Weighting**: Current observations (75%) + Historical intelligence (25%)

### TOON Format
Token-Oriented Object Notation for network events:
- L3+ only (IP, TCP, UDP, DNS, HTTP, TLS, etc.)
- Null/placeholder filtering
- Normalized field names (`si`, `di`, `sp`, `dp`, `pr`)
- Evidence-based protocol detection

---

## 🛠 Dependencies

Core:
- Python 3.11+
- Streamlit (UI)
- DuckDB (database)
- PyShark/TShark (PCAP ingestion)
- Pydantic (schemas)

Optional:
- Transformers (LLM)
- Torch (AI models)
- Zeek (enrichment)
- Snort 3 (IDS)

---

##  Architecture

### Components Merged

**From One_Blink:**
- PCAP ingestion engine
- Real-time analysis workflow
- Charts and visualizations
- TShark/PyShark optimization

**From SecAI Reporter:**
- Professional report templates
- Historical correlation
- MITRE ATT&CK mapping
- Ticket management system

**New (Ultimate):**
- TOON normalization
- 75/25 weighted scoring
- Unified analyzer orchestration
- Multi-format reporting

---

## 🚦 System Requirements

**Minimum:**
- CPU: 4 cores
- RAM: 8 GB
- Disk: 10 GB free

**Recommended:**
- CPU: 8+ cores
- RAM: 16 GB
- Disk: 50 GB free
- Optional GPU for Vision AI

**Software:**
- Linux/macOS/Windows
- Python 3.11+
- TShark 4.0+
- Optional: Zeek 6.0+, Snort 3.0+

---

##  Usage Examples

### Example 1: Analyze PCAP via UI
1. Launch dashboard: `./run_dashboard.sh`
2. Navigate to "PCAP Analysis"
3. Upload file
4. Click "Start Analysis"
5. Download report

### Example 2: CLI Batch Processing
```bash
for pcap in samples/*.pcap; do
    python src/cli/soc_cli.py analyze "$pcap" --output json
done
```

### Example 3: Python API
```python
from src.unified.analysis.unified_analyzer import UnifiedAnalyzer

analyzer = UnifiedAnalyzer()
result = analyzer.analyze_pcap(
    pcap_path=Path("sample.pcap"),
    create_ticket=True,
    output_format="html"
)

print(f"Report: {result['report_path']}")
print(f"TTPs: {len(result['ttps'])}")
```

---

## 🤝 Contributing

This is a unified platform built from:
- One_Blink (PCAP analysis)
- SecAI Reporter (professional reporting)
- Ultimate Prompt (AI analysis)

---

##  License

See individual component licenses in legacy folders.

---

##  Roadmap

- [ ] FastAPI REST API
- [ ] Real-time streaming analysis
- [ ] OpenCTI integration
- [ ] Advanced ML models
- [ ] Distributed processing
- [ ] Cloud deployment options

---

##  Credits

**SOC_Intelligence Platform v1.0**

Unified by: SOC Intelligence Team
Built with: Python, Streamlit, DuckDB, Transformers

---

##  Support

For issues and questions, check:
- Documentation: `docs/`
- Implementation Plan: `.gemini/brain/<ID>/implementation_plan.md`
- Ultimate Prompt: `src/unified/ai/ultimate_prompt.py`

---

** SOC_Intelligence - Enterprise SOC Analysis, Simplified**
