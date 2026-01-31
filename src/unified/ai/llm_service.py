"""
Local LLM Service for SOC_Intelligence

CPU-only inference using Ultimate Prompt for enterprise SOC reporting.
Supports air-gapped deployment.
"""

import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import json

# Import Ultimate Prompt
from src.unified.ai.ultimate_prompt import ULTIMATE_SOC_PROMPT
from src.unified.models.schemas import AnalysisReport, TOONEvent, WeightedThreatScore, TTP

logger = logging.getLogger(__name__)


class LocalLLMService:
    """
    Local CPU-only LLM service for air-gapped environments
    
    Features:
    - Uses Ultimate Prompt as system prompt
    - CPU inference (no GPU required)
    - Fallback to template-based generation
    - 14-section enterprise report output
    """
    
    def __init__(self, model_path: Optional[str] = None, use_gpu: bool = False):
        """
        Initialize LLM service
        
        Args:
            model_path: Path to local model (e.g., Mistral-7B)
            use_gpu: Enable GPU if available (default: False for air-gap)
        """
        self.model_path = model_path
        self.use_gpu = use_gpu
        self.pipe = None
        self.model_loaded = False
        
        if model_path:
            self._load_model()
        else:
            logger.warning("No model path provided - using template fallback only")
    
    def _load_model(self):
        """Load local LLM model"""
        try:
            from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
            import torch
            
            logger.info(f"Loading model from {self.model_path}...")
            
            # Device setup
            device = "cuda" if self.use_gpu and torch.cuda.is_available() else "cpu"
            logger.info(f"Using device: {device}")
            
            # Load model with optimizations for CPU
            model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                torch_dtype=torch.float32 if device == "cpu" else torch.float16,
                low_cpu_mem_usage=True,
                device_map=None if device == "cpu" else "auto"
            )
            
            tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            
            # Create pipeline
            self.pipe = pipeline(
                "text-generation",
                model=model,
                tokenizer=tokenizer,
                device=device,
                max_new_tokens=4096,
                do_sample=True,
                temperature=0.3,  # Low for determinism
                top_p=0.9
            )
            
            self.model_loaded = True
            logger.info("Model loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            logger.warning("Will use template fallback for report generation")
            self.model_loaded = False
    
    def generate_analysis(
        self,
        toon_events: List[TOONEvent],
        ticket_context: Optional[Dict[str, Any]] = None,
        historical_stats: Optional[Dict[str, Any]] = None,
        detected_ttps: Optional[List[TTP]] = None
    ) -> str:
        """
        Generate 14-section analysis report using Ultimate Prompt
        
        Args:
            toon_events: List of TOON normalized events
            ticket_context: Optional ticket metadata
            historical_stats: Optional historical statistics for 75/25
            detected_ttps: Optional pre-detected MITRE TTPs
        
        Returns:
            Markdown formatted report (14 sections)
        """
        
        # Build TOON input for prompt
        toon_input = self._format_toon_input(
            toon_events,
            ticket_context,
            historical_stats,
            detected_ttps
        )
        
        # Generate with LLM if available, else fallback
        if self.model_loaded and self.pipe:
            return self._generate_with_llm(toon_input)
        else:
            return self._generate_with_template(toon_input, toon_events, historical_stats)
    
    def _format_toon_input(
        self,
        events: List[TOONEvent],
        ticket_context: Optional[Dict],
        historical_stats: Optional[Dict],
        ttps: Optional[List[TTP]]
    ) -> str:
        """Format TOON data for Ultimate Prompt"""
        
        sections = []
        
        # A) TICKET CONTEXT (if available)
        if ticket_context:
            sections.append("TICKET CONTEXT:")
            sections.append(f"- Ticket ID: {ticket_context.get('ticket_id', 'N/A')}")
            sections.append(f"- IOC: {ticket_context.get('ioc_value', 'N/A')} ({ticket_context.get('ioc_type', 'N/A')})")
            sections.append(f"- Trigger: {ticket_context.get('trigger_type', 'N/A')}")
            sections.append(f"- Window: {ticket_context.get('window_start', 'N/A')} to {ticket_context.get('window_end', 'N/A')}")
            sections.append("")
        
        # B) CURRENT WINDOW DATA (TOON events)
        sections.append("CURRENT WINDOW DATA (TOON-normalized L3+):")
        sections.append(f"Total events: {len(events)}")
        
        # Summary statistics
        protocols = {}
        sources = set()
        destinations = set()
        
        for event in events:
            protocols[event.pr] = protocols.get(event.pr, 0) + 1
            if event.si:
                sources.add(event.si)
            if event.di:
                destinations.add(event.di)
        
        sections.append(f"Distinct sources: {len(sources)}")
        sections.append(f"Distinct destinations: {len(destinations)}")
        sections.append(f"Protocols: {', '.join(f'{k} ({v})' for k, v in protocols.items())}")
        sections.append("")
        
        # Sample events (first 10 for context)
        sections.append("Sample TOON Events:")
        for i, event in enumerate(events[:10]):
            sections.append(f"[{i+1}] t={event.t}, {event.si}:{event.sp} -> {event.di}:{event.dp}, pr={event.pr}")
            if event.dns_query:
                sections.append(f"    DNS: {event.dns_query}")
            if event.http_host:
                sections.append(f"    HTTP: {event.http_method} {event.http_host}{event.http_uri or ''}")
            if event.tls_sni:
                sections.append(f"    TLS SNI: {event.tls_sni}")
                if event.tls_ja3:
                    sections.append(f"    JA3: {event.tls_ja3}")
        sections.append("")
        
        # C) HISTORICAL INTELLIGENCE
        if historical_stats:
            sections.append("HISTORICAL INTELLIGENCE (25% weight):")
            sections.append(f"- Previous tickets: {historical_stats.get('total_tickets', 0)}")
            sections.append(f"- True Positives (TP): {historical_stats.get('tp_count', 0)}")
            sections.append(f"- False Positives (FP): {historical_stats.get('fp_count', 0)}")
            sections.append(f"- Threat ratio: {historical_stats.get('threat_ratio', 0.5):.2f}")
            sections.append("")
        
        # D) MITRE ATT&CK TTPs (if detected)
        if ttps:
            sections.append("DETECTED TTPs:")
            for ttp in ttps:
                sections.append(f"- {ttp.technique_id}: {ttp.technique_name} ({ttp.tactic})")
                sections.append(f"  Confidence: {ttp.confidence}")
            sections.append("")
        
        return "\n".join(sections)
    
    def _generate_with_llm(self, toon_input: str) -> str:
        """Generate report using LLM"""
        try:
            messages = [
                {"role": "system", "content": ULTIMATE_SOC_PROMPT},
                {"role": "user", "content": toon_input}
            ]
            
            logger.info("Generating analysis with LLM...")
            output = self.pipe(messages, max_new_tokens=4096)
            
            # Extract assistant response
            report = output[0]['generated_text'][-1]['content']
            logger.info("LLM analysis complete")
            
            return report
            
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            logger.warning("Falling back to template")
            return self._generate_with_template(toon_input, [], None)
    
    def _generate_with_template(
        self,
        toon_input: str,
        events: List[TOONEvent],
        historical_stats: Optional[Dict]
    ) -> str:
        """
        Fallback template-based report generation
        (For when LLM is unavailable)
        """
        
        logger.info("Generating report with template fallback")
        
        # Basic template following 14-section structure
        report = f"""
═══════════════════════════════════════════════════════════════════════════════
SOC INTELLIGENCE ANALYSIS REPORT
═══════════════════════════════════════════════════════════════════════════════

**Report ID**: TEMPLATE-FALLBACK
**Generated**: {from datetime import datetime; datetime.now().isoformat()}
**Analyst Engine**: SOC_Intelligence Ultimate v1.0 (Template Mode)
**Data Sources**: PCAP (TShark), DuckDB

═══════════════════════════════════════════════════════════════════════════════
1) EXECUTIVE SECURITY VERDICT
═══════════════════════════════════════════════════════════════════════════════

**Verdict**: NEEDS_MORE_EVIDENCE
**Severity**: INFO
**Confidence**: LOW (0.30)
**Immediate Action**: INVESTIGATE

**Rationale**: Template-based analysis generated due to LLM unavailability. 
Manual review required for final verdict.

Analyzed {len(events)} network events. Full LLM analysis recommended for 
comprehensive threat assessment.

═══════════════════════════════════════════════════════════════════════════════
2) EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════════════════════

**What Happened:**
- Processed {len(events)} network events
- Template-based analysis only (LLM unavailable)
- Requires manual analyst review

**Business Risk:** Cannot be determined without LLM analysis

**Immediate Decisions:** Load LLM model for full analysis capability

═══════════════════════════════════════════════════════════════════════════════
NOTE: TEMPLATE MODE
═══════════════════════════════════════════════════════════════════════════════

This report was generated using template fallback mode because the LLM model
was not available. For full 14-section enterprise analysis with:

- Behavioral analysis
- Weighted threat scoring (75/25)
- MITRE ATT&CK mapping
- Evidence-based recommendations

Please configure the LLM model path in config and restart the service.

**TOON Input Provided:**
{toon_input}

═══════════════════════════════════════════════════════════════════════════════
END OF TEMPLATE REPORT
═══════════════════════════════════════════════════════════════════════════════
"""
        
        return report
    
    def health_check(self) -> Dict[str, Any]:
        """Check LLM service health"""
        return {
            "model_loaded": self.model_loaded,
            "model_path": self.model_path,
            "device": "cpu" if not self.use_gpu else "cuda",
            "fallback_available": True,
            "ultimate_prompt_loaded": True
        }
