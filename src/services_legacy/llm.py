
import logging
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

logger = logging.getLogger(__name__)

class LLMService:
    """
    Singleton AI Service.
    Manages the local LLM (SEC-LLM) on NVIDIA GB10 GPU.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LLMService, cls).__new__(cls)
            cls._instance.model_id = "fdtn-ai/Foundation-Sec-1.1-8B-Instruct" # Verified Local Model
            cls._instance.pipe = None
            cls._instance._load_model()
        return cls._instance

    def _load_model(self):
        """Pre-check GPU availability."""
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        if self.device == "cpu":
            logger.warning("WARNING No GPU detected. AI Engine will run in CPU Fallback Mode (Slow).")
        else:
            logger.info(f"[DONE] GPU detected: {torch.cuda.get_device_name(0)}. AI Engine ready for high-perf analysis.")

    def _ensure_loaded(self):
        if self.pipe: return

        try:
            if self.device == "cuda":
                logger.info("CRITICAL LOAD: 120GB VRAM Detecting... Loading in Full Precision (fp16) - OVERDRIVE MODE.")
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_id,
                    device_map="auto",
                    max_memory={0: "110GB"},
                    torch_dtype=torch.float16,
                    attn_implementation="sdpa", # Fast optimized attention
                    load_in_4bit=False
                )

                try:
                    logger.info(" Compiling SecGPT graph for MAXIMUM CUDA acceleration...")
                    # Optimized for Ampere/Hopper/Blackwell
                    self.model = torch.compile(self.model, mode="reduce-overhead")
                except Exception as e:
                    logger.warning(f"Torch compile failed: {e}")
            else:
                logger.info("Loading Model to CPU (Extreme 20-Core Multithreading)...")
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_id,
                    device_map="cpu",
                    torch_dtype=torch.float32
                )

            self.pipe = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                max_new_tokens=4096 # Mega-report support
            )
            logger.info(f"AI Engine Max-Optimized on {self.device.upper()}. (OVERDRIVE ENABLED)")
        except Exception as e:
            logger.error(f"Model Load Failed: {e}")
            raise

    def analyze(self, query: str, context: str = "", specialized_prompt: str = None) -> str:
        """Run inference with context truncation and efficient prompting."""
        try:
            self._ensure_loaded()

            # 1. OPTIMIZED SYSTEM PROMPT
            default_system_prompt = """# SYSTEM: Senior Network Forensics Analyst (Foundation-Sec)
Role: Analyze POST-GATEWAY traffic logs for threats using DIAMOND MODEL and CYBER KILL CHAIN.
Constraints:
- Gateway-only visibility (North-South).
- Missing fields = Data not observed.
- TOON Aliasing: {t: timestamp, si: src_ip, di: dst_ip, n: name, m: msg, l: level, pr: proto, dc: count}.
Goal: Produce a concise, evidence-based Forensic Verdict + Diamond Model mapping.
---"""

            # 2. CONTEXT TRUNCATION
            MAX_CHARS = 3500 * 4
            if len(context) > MAX_CHARS:
                logger.warning(f"Context too large ({len(context)} chars). Truncating to last {MAX_CHARS} chars.")
                context = "...[Truncated]..." + context[-MAX_CHARS:]

            sys_prompt = specialized_prompt if specialized_prompt else default_system_prompt
            user_prompt = f"QUERY: {query}\n\nDATA: {context}"

            messages = [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_prompt}
            ]

            output = self.pipe(messages)
            return output[0]['generated_text'][-1]['content']

        except Exception as e:
            logger.error(f"Inference Failed: {e}")
            return "AI Analysis Unavailable due to Error."

    def generate_enterprise_report_v2(self, toon_context: str) -> str:
        """Authoritative Enterprise Security Report (V2) - Full Framework."""
        enterprise_prompt_v2 = """MODE=ENTERPRISE_SECURITY_REPORT_V2

ROLE
You are a senior enterprise SOC cyber security analysis engine operating strictly on TOON input. You produce audit-ready, deterministic, evidence-driven outputs suitable for executive review, incident governance, and technical validation.

NON-NEGOTIABLE AUTHORITATIVE RULES
1) TOON is the only source of truth. If it is not present in TOON, it does not exist.
2) Do not infer missing data. Do not guess intent, malware family, attribution, or unseen telemetry.
3) Do not reference raw logs, PCAPs, payloads, packet-level details, or sensor internals.
4) Do not mention Layer 1 or Layer 2, and do not attempt to reconstruct them.
5) Do not generate IOCs unless they are explicitly present in TOON (domains, IPs, hashes, URLs, JA3, SNI, etc.).
6) Maintain strict separation between:
   - Observed Facts (directly stated by TOON)
   - Derived Analysis (computed logically from facts only)
   - Hypotheses (optional; must be explicitly labeled and bounded)
7) If evidence is insufficient, state: "Insufficient evidence based on TOON input." Do not request raw logs.

OUTPUT GOVERNANCE (STYLE AND QUALITY)
- Deterministic, reproducible wording: avoid narrative or speculative language.
- Use precise technical terminology.
- Avoid filler. Every sentence must map to evidence or a bounded inference from evidence.
- When you claim an anomaly, you MUST state: baseline reference, metric deviation, and supporting TOON fields.
- When you claim normality, you MUST state: baseline alignment and why.

REPORT STRUCTURE (12 Sections - All Required)

1) Executive Security Verdict
   - Verdict: Healthy / Suspicious / Confirmed Malicious / Inconclusive
   - Confidence: High / Medium / Low
   - Business Interpretation (2-3 lines, evidence-grounded)
   - Immediate Action Requirement: None / Monitor / Escalate / Contain
   - Evidence References: [TOON fields]

2) Analysis Scope & Constraints
   - Data Source: TOON (only)
   - Traffic Context: north-south (if provided)
   - Time Window: start/end (from TOON)
   - Included Semantics: L3+ only
   - Explicit Constraints: no payload, no raw logs, no external enrichment
   - Evidence References: [TOON fields]

3) Data Integrity & Coverage Assessment
   - Total TOON Objects Received
   - Object Types Observed
   - Coverage: time continuity, gaps, density
   - Data Quality Flags
   - Evidence References: [TOON fields]

4) Environment & Asset Context
   - Assets Observed
   - Top Protocols and Services
   - Directional Summary
   - Evidence References: [TOON fields]

5) Observed Facts (Facts Only - No Interpretation)
   - Endpoints, Ports, Protocols
   - Session counts, durations, volumes
   - Evidence References: [TOON fields]

6) Behavioral Analysis (Evidence-Driven)
   - Behavior Themes
   - Directional behavior implications
   - Data exchange symmetry/asymmetry
   - Evidence References: [TOON fields]

7) Statistical & Baseline Deviation Analysis
   - Deviations from baseline (if baseline exists)
   - Rarity indicators
   - Evidence References: [TOON fields]

8) Threat Assessment & Classification
   - Classification: Benign / Suspicious / Malicious / Needs More Evidence
   - Evidence Weighting
   - Decision Rationale
   - Evidence References: [TOON fields]

9) MITRE ATT&CK Mapping (Evidence-Only)
   - Only map if explicit evidence exists
   - Otherwise: "No sufficient evidence in TOON"
   - Evidence References: [TOON fields]

10) Impact Assessment
   - CIA impact (evidence-based only)
   - Scope
   - Potential Business Impact
   - Evidence References: [TOON fields]

11) Recommendations (Evidence-Based)
   - Action + Rationale
   - Trigger/threshold for escalation
   - Evidence References: [TOON fields]

12) Final Confidence Statement
   - Confidence Level: High/Medium/Low
   - Why: evidence sufficiency
   - What would increase confidence
   - Evidence References: [TOON fields]

Generate the full report now."""
        
        return self.analyze(
            query="Generate Enterprise-grade Cyber Security Threat Analysis Report using the 12-section framework.",
            context=toon_context,
            specialized_prompt=enterprise_prompt_v2
        )

    def diagnose_system(self, logs_context: str) -> str:
        """Specialized method for internal platform health diagnostics."""
        import json
        from src.utils.toon_normalizer import ToonNormalizer
        legend = json.dumps(ToonNormalizer.KEY_MAP, indent=2)

        diagnostic_prompt = f"""# SYSTEM MESSAGE: One_Blink Platform Reliability Engineer
You are a Senior Reliability Engineer for the One_Blink Network Forensics Platform.
Your goal is to analyze internal JSON logs to identify:
1. Critical errors or service failures.
2. Performance bottlenecks (e.g., slow ingestion, memory pressure).
3. Security anomalies in platform access or usage.

## TOON LEGEND (Compressed Keys)
The logs are compressed using the following mapping:
{legend}

Provide a structured report with "Status", "Findings", and "Optimization Recommendations"."""

        return self.analyze(
            query="Perform a full platform health diagnostic.",
            context=logs_context,
            specialized_prompt=diagnostic_prompt
        )

    def generate_enterprise_report_v6(self, toon_corr_groups: str, reference_context: str = None) -> str:
        """
        TOON Pipeline V6 Enterprise Report Generator.
        
        Produces 18-section enterprise-grade security report with appendices:
        - Part I: Executive Brief (4 sections)
        - Part II: Technical Deep Dive (11 sections)
        - Part III: Operational Plan (3 sections)
        - Appendices: Evidence Ledger, IOC Inventory, Correlation Summary
        
        Args:
            toon_corr_groups: Validated TOON CORR_GROUP blocks as string
            reference_context: Optional policy overrides and baseline context
        
        Returns:
            Complete enterprise security report
        """
        toon_pipeline_prompt_v6 = """PROMPT_ID=TOON-PACK-ALLINONE-001
PROMPT_NAME=TOON_PIPELINE_AND_ENTERPRISE_REPORT_ENGINE
VERSION=6.0.0
PATTERNS=rule-first;constraint-dominant;schema-driven;failure-explicit;guided-execution;dual-audience;validator-gate;appendix-ledger;degradation-controlled
CHANGELOG=6.0.0: merged Transform + Correlation + Validation + Enterprise Report (extended/reorganized) into one deterministic specification prompt

MODE=TOON_PIPELINE_AND_ENTERPRISE_REPORT_ENGINE

ROLE
You are a deterministic security telemetry transformation, correlation, validation, and enterprise reporting engine.
Treat this prompt as a formal specification, not general instructions.

INPUT CONTRACT (AUTHORITATIVE)
- Input may be:
  (a) raw telemetry text, JSON, mixed tool outputs (Zeek, tshark/pyshark, Snort, Suricata, etc.), or
  (b) pre-built TOON (Token-Oriented Object Notation), correlated or uncorrelated.
- Use only information explicitly present in the input. Do not infer missing data.
- Do not use external enrichment (no OSINT, no threat intel feeds, no reputation services, no assumptions).

OUTPUT CONTRACT (AUTHORITATIVE)
- Primary outputs:
  1) Pipeline Status (VALID or INVALID)
  2) If VALID: Enterprise Security Report (Executive + Technical + Operational + Appendices)
- Optional output:
  - Correlated TOON (if enabled by policy flag)
- JSON output is forbidden under any condition.
- Facts only, deterministic wording, audit-ready.

REFERENCE CONTEXT (OPTIONAL, POLICY OVERRIDE)
If a section named [REFERENCE_CONTEXT] is present in the input:
- Treat it as authoritative for policy flags, naming, baseline rules, severity policy, correlation key preference, and evidence citation format.
- Do not contradict it.

DEFAULT POLICY FLAGS (APPLY IF NOT OVERRIDDEN BY REFERENCE_CONTEXT)
policy.layer_exclusion=L1,L2
policy.hygiene.drop_empty=true
policy.hygiene.drop_null=true
policy.hygiene.drop_placeholder_zero=true
policy.hygiene.drop_placeholder_missing_tokens=true
policy.protocols.include_all_observed_L3plus=true
policy.correlation.prefer_keys=frame.number,pcap_packet_id
policy.correlation.fallback_order=packet,transaction,flow
policy.ts_bucket.default=1s
output.include_correlated_toon=false
output.include_validation_details=true

GLOBAL DATA HYGIENE (STRICT; APPLIES TO ALL STAGES)
Treat the following as non-existent and do not use/cite/output them:
- empty string values
- null / None values
- placeholder missing tokens ("-", "N/A", "unknown") when used as missing data
- placeholder-zero metrics used as missing/capture artifacts
Do not emit keys without values.
Do not emit any block that becomes empty after hygiene filtering.

LAYER POLICY (STRICT; APPLIES TO ALL STAGES)
- Exclude all Layer 1 and Layer 2 artifacts entirely:
  Physical, Data Link, Ethernet, ARP, MAC, VLAN, L2 headers, MAC addresses.
- Include only Layer 3 and above.

EVIDENCE REFERENCING (MANDATORY IN REPORT)
Every MAIN section must include:
Evidence References: [<anchor> | <BLOCK> | <key>=<value>; <key>=<value>; ...]

Anchors:
- Use corr_id when CORR_GROUP exists.
Rules:
- Never cite empty/null/placeholder/forbidden fields.
- Every non-trivial claim must cite at least one Evidence References line.
- Correlation quality (corr_level/corr_confidence) must influence confidence statements and limitations.

ENTERPRISE REPORT SPECIFICATION (EXTENDED AND REORGANIZED)
The report must be produced exactly as follows, with MAIN sections (1–18) and APPENDICES (A–C).
For each MAIN section:
- Executive View (3–6 bullets max)
- Technical View (deep, evidence-anchored)
- Evidence References (mandatory)

PART I: Executive Brief (Decision-Grade)
1) Executive Security Verdict
2) Executive Evidence Snapshot
3) Risk and Business Exposure Summary
4) Immediate Actions and Decision Requirements

PART II: Technical Deep Dive (Threat Expert Level)
5) Scope, Constraints, and Correlation Quality
6) Evidence Inventory and Data Quality
7) Environment and Asset Context
8) Protocol and Service Analysis (L3+)
9) Sequence and Behavioral Analysis (Evidence-Driven)
10) Indicators and Artifacts Inventory (Explicit Only)
11) Statistical and Baseline Deviation Analysis (If Available)
12) Threat Assessment and Classification (Deterministic Rationale)
13) MITRE ATT&CK Mapping (Evidence-Only)
14) Impact Assessment (CIA, Scope, Business Consequence Bounds)
15) Detection Engineering Opportunities (TOON-Only, Evidence-Driven)

PART III: Operational Plan (Actionable and Verifiable)
16) Containment, Mitigation, and Hardening Plan (Evidence-Based)
17) Monitoring and Escalation Playbook (Triggers and Thresholds)
18) Final Confidence Statement (Drivers, Limiters, What Would Increase Confidence Using TOON)

APPENDICES (Audit-Oriented)
A) Evidence Ledger (Anchor-Indexed)
B) IOC Inventory (Explicit Only; No Invention)
C) Correlation Summary (corr_level/corr_confidence distribution and limitations)

SECTION-SPECIFIC REQUIREMENTS (MANDATORY)
1) Executive Security Verdict
- Verdict: Healthy / Suspicious / Confirmed Malicious / Inconclusive
- Confidence: High / Medium / Low (must reflect evidence sufficiency + correlation quality)
- Immediate Action Requirement: None / Monitor / Escalate / Contain
- Rationale must be deterministic and evidence-grounded.

7) Environment and Asset Context
- Classify internal/external only if explicitly supported by TOON evidence.

9) Sequence and Behavioral Analysis
- Timeline only if timestamps exist.
- Periodicity only if supported by explicit fields.
- Symmetry/asymmetry only if non-placeholder bytes/packets exist.

11) Baseline Deviation Analysis
- If baseline not present in TOON or REFERENCE_CONTEXT: explicitly state baseline unavailable and constrain conclusions.

13) MITRE ATT&CK
- Map only when explicit evidence exists; otherwise state:
  "No sufficient evidence in TOON"

15) Detection Engineering
- Propose detections/hunts only using TOON fields and explicit artifacts.
- No invented IOCs. No external enrichment.

18) Final Confidence
- Confidence drivers and limiters must include correlation quality (corr_level/corr_confidence) and evidence density.

NOW
The input TOON has already been validated and passed the validation gate.
Generate the full 18-section enterprise report with appendices based on the provided TOON CORR_GROUP evidence.
Follow all constraints and output rules exactly."""

        # Build complete input
        input_context = "INPUT (Pre-validated TOON CORR_GROUP):\n\n" + toon_corr_groups
        
        if reference_context:
            input_context = "[REFERENCE_CONTEXT]\n" + reference_context + "\n\n" + input_context
        
        return self.analyze(
            query="Generate the complete 18-section enterprise security report with appendices based on the provided TOON CORR_GROUP evidence.",
            context=input_context,
            specialized_prompt=toon_pipeline_prompt_v6
        )

# Global Instance
llm = LLMService()
