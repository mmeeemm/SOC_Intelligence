"""
CPU-Only LLM Inference Wrapper

Provides CPU-optimized inference for generating AI narratives.
Uses Hugging Face Transformers with no GPU dependencies.
"""

import logging
import os
from typing import Any, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from LLM inference."""
    detailed_analysis: str
    technical_conclusion: str
    confidence_level: str  # low, medium, high
    confidence_score: float  # 0.0 to 1.0
    success: bool
    error: Optional[str] = None


class CPUInferenceWrapper:
    """
    CPU-only LLM inference wrapper.
    
    Uses Hugging Face Transformers for local inference without GPU.
    Optimized for air-gapped environment with local model files.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize LLM wrapper with configuration.
        
        Args:
            config: LLM configuration from config.yaml
        """
        self.config = config
        self.model_path = config.get('model_path', '/opt/models/mistral-7b-instruct')
        self.max_tokens = config.get('max_new_tokens', 2048)
        self.temperature = config.get('temperature', 0.3)
        self.top_p = config.get('top_p', 0.9)
        self.do_sample = config.get('do_sample', True)
        self.fallback_enabled = config.get('fallback_to_template', True)
        
        self.model = None
        self.tokenizer = None
        self._loaded = False
    
    def load_model(self) -> bool:
        """
        Load model and tokenizer.
        
        Returns:
            True if successful, False otherwise
        """
        if self._loaded:
            return True
        
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
            
            logger.info(f"Loading model from {self.model_path}...")
            
            # Configure for CPU
            torch_dtype = getattr(torch, self.config.get('torch_dtype', 'float16'), torch.float16)
            
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_path,
                local_files_only=True,
                trust_remote_code=False
            )
            
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                local_files_only=True,
                torch_dtype=torch_dtype,
                device_map='cpu',
                low_cpu_mem_usage=self.config.get('low_cpu_mem_usage', True),
                trust_remote_code=False
            )
            
            self._loaded = True
            logger.info("Model loaded successfully")
            return True
            
        except ImportError as e:
            logger.error(f"Missing LLM dependencies: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def generate_analysis(self, 
                          aggregates: Dict[str, Any],
                          historical_stats: Dict[str, Any],
                          ttps: list,
                          ticket_info: Dict[str, Any]) -> LLMResponse:
        """
        Generate AI analysis narrative.
        
        Args:
            aggregates: Zeek log aggregates
            historical_stats: Historical ticket statistics
            ttps: Detected TTPs
            ticket_info: Ticket metadata
            
        Returns:
            LLMResponse with analysis and conclusion
        """
        # Try LLM inference first
        if self.load_model():
            try:
                return self._generate_with_llm(aggregates, historical_stats, ttps, ticket_info)
            except Exception as e:
                logger.error(f"LLM inference failed: {e}")
                if self.fallback_enabled:
                    logger.info("Falling back to template-based generation")
                    return self._generate_template_fallback(aggregates, historical_stats, ttps, ticket_info)
                return LLMResponse(
                    detailed_analysis="",
                    technical_conclusion="",
                    confidence_level="low",
                    confidence_score=0.0,
                    success=False,
                    error=str(e)
                )
        elif self.fallback_enabled:
            return self._generate_template_fallback(aggregates, historical_stats, ttps, ticket_info)
        else:
            return LLMResponse(
                detailed_analysis="",
                technical_conclusion="",
                confidence_level="low",
                confidence_score=0.0,
                success=False,
                error="Model not available and fallback disabled"
            )
    
    def _build_prompt(self, aggregates: Dict[str, Any],
                      historical_stats: Dict[str, Any],
                      ttps: list,
                      ticket_info: Dict[str, Any]) -> str:
        """Build the analysis prompt for the LLM."""
        
        # Extract key metrics
        total_sightings = aggregates.get('total_ioc_sightings', 0)
        distinct_src = aggregates.get('distinct_src_ip_count', 0)
        distinct_dst = aggregates.get('distinct_dst_ip_count', 0)
        protocols = [p.get('protocol') for p in aggregates.get('protocol_coverage', [])]
        
        hist_total = historical_stats.get('total_tickets', 0)
        hist_tp = historical_stats.get('threat_count', 0)
        hist_fp = historical_stats.get('false_positive_count', 0)
        threat_ratio = historical_stats.get('threat_ratio')
        
        ttp_summary = ", ".join([f"{t.get('technique_id')} ({t.get('technique_name')})" for t in ttps[:3]])
        
        prompt = f"""You are a SOC analyst writing a technical report for a security ticket.

TICKET INFORMATION:
- Ticket ID: {ticket_info.get('id')}
- IOC Type: {ticket_info.get('ioc_type')}
- IOC Value: {ticket_info.get('ioc_value')}
- Trigger: {ticket_info.get('trigger_type')}

CURRENT WINDOW OBSERVATIONS (T0 ± 24 hours):
- Total IOC sightings: {total_sightings}
- Distinct source IPs: {distinct_src}
- Distinct destination IPs: {distinct_dst}
- Protocols involved: {', '.join(protocols) if protocols else 'None'}
- Log types with matches: {list(aggregates.get('sightings_by_log_type', {}).keys())}

HISTORICAL TICKET STATISTICS (Same IOC):
- Total previous tickets: {hist_total}
- Confirmed Threats (TP): {hist_tp}
- Confirmed False Positives (FP): {hist_fp}
- Historical Threat Ratio: {f'{threat_ratio:.1%}' if threat_ratio is not None else 'N/A (no resolved tickets)'}

DETECTED TTPs:
{ttp_summary if ttp_summary else 'No specific TTPs detected'}

ANALYSIS WEIGHTING:
- 75% weight on current window behavior
- 25% weight on historical ticket outcomes

TASK:
Write TWO sections:

1. DETAILED COMMUNICATIONS ANALYSIS:
A technical, protocol-aware summary of what was observed. Mention:
- Which protocols showed activity and what that indicates
- Multi-protocol presence if applicable
- Temporal patterns if notable
- Peer/asset involvement patterns
- Any protocol-specific indicators (DNS query types, HTTP methods, TLS versions, etc.)

2. TECHNICAL CONCLUSION:
Apply the 75/25 weighting to provide:
- Assessment: Is this Threat-consistent or False-positive-consistent?
- Confidence level (low/medium/high) with numeric score (0.0-1.0)
- Key factors driving the conclusion
IMPORTANT: Explicitly state the historical statistics numbers in your conclusion.

Be direct and technical. No filler text. Do not assume endpoint compromise - only network behavior.
"""
        return prompt
    
    def _generate_with_llm(self, aggregates: Dict[str, Any],
                           historical_stats: Dict[str, Any],
                           ttps: list,
                           ticket_info: Dict[str, Any]) -> LLMResponse:
        """Generate analysis using the LLM."""
        import torch
        
        prompt = self._build_prompt(aggregates, historical_stats, ttps, ticket_info)
        
        inputs = self.tokenizer(prompt, return_tensors="pt")
        
        with torch.no_grad():
            outputs = self.model.generate(
                inputs.input_ids,
                max_new_tokens=self.max_tokens,
                temperature=self.temperature,
                top_p=self.top_p,
                do_sample=self.do_sample,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Parse response into sections
        detailed_analysis, conclusion, confidence_level, confidence_score = self._parse_llm_response(response)
        
        return LLMResponse(
            detailed_analysis=detailed_analysis,
            technical_conclusion=conclusion,
            confidence_level=confidence_level,
            confidence_score=confidence_score,
            success=True
        )
    
    def _parse_llm_response(self, response: str) -> tuple:
        """Parse LLM response into structured sections."""
        # Simple parsing - look for section markers
        detailed = ""
        conclusion = ""
        
        if "DETAILED COMMUNICATIONS ANALYSIS:" in response:
            parts = response.split("DETAILED COMMUNICATIONS ANALYSIS:")
            if len(parts) > 1:
                rest = parts[1]
                if "TECHNICAL CONCLUSION:" in rest:
                    detailed = rest.split("TECHNICAL CONCLUSION:")[0].strip()
                    conclusion = rest.split("TECHNICAL CONCLUSION:")[1].strip()
                else:
                    detailed = rest.strip()
        
        # Extract confidence from conclusion
        confidence_level = "medium"
        confidence_score = 0.5
        
        conclusion_lower = conclusion.lower()
        if "high confidence" in conclusion_lower or "high)" in conclusion_lower:
            confidence_level = "high"
            confidence_score = 0.8
        elif "low confidence" in conclusion_lower or "low)" in conclusion_lower:
            confidence_level = "low"
            confidence_score = 0.3
        
        # Try to extract numeric score
        import re
        score_match = re.search(r'(\d+\.?\d*)\s*(confidence|score)', conclusion_lower)
        if score_match:
            try:
                score = float(score_match.group(1))
                if score <= 1.0:
                    confidence_score = score
                elif score <= 100:
                    confidence_score = score / 100
            except ValueError:
                pass
        
        return detailed, conclusion, confidence_level, confidence_score
    
    def _generate_template_fallback(self, aggregates: Dict[str, Any],
                                     historical_stats: Dict[str, Any],
                                     ttps: list,
                                     ticket_info: Dict[str, Any]) -> LLMResponse:
        """Generate analysis using templates when LLM is unavailable."""
        
        # Extract metrics
        total_sightings = aggregates.get('total_ioc_sightings', 0)
        distinct_src = aggregates.get('distinct_src_ip_count', 0)
        distinct_dst = aggregates.get('distinct_dst_ip_count', 0)
        protocols = [p.get('protocol') for p in aggregates.get('protocol_coverage', [])]
        log_types = list(aggregates.get('sightings_by_log_type', {}).keys())
        
        hist_total = historical_stats.get('total_tickets', 0)
        hist_tp = historical_stats.get('threat_count', 0)
        hist_fp = historical_stats.get('false_positive_count', 0)
        threat_ratio = historical_stats.get('threat_ratio')
        
        # Build detailed analysis
        protocol_str = ", ".join(protocols) if protocols else "unspecified protocols"
        log_type_str = ", ".join(log_types) if log_types else "various log types"
        
        detailed_analysis = f"""Within the T0 ± 24 hour analysis window, the indicator was observed {total_sightings} times across {log_type_str}. 

Traffic involved {distinct_src} distinct source IP addresses and {distinct_dst} distinct destination IP addresses, communicating via {protocol_str}.
"""
        
        # Add protocol-specific details
        proto_details = aggregates.get('protocol_specific_details', {})
        if proto_details.get('dns'):
            dns = proto_details['dns']
            detailed_analysis += f"\nDNS: {dns.get('unique_queries', 0)} unique queries observed"
            if dns.get('query_types'):
                detailed_analysis += f", query types: {dns['query_types']}"
        
        if proto_details.get('http'):
            http = proto_details['http']
            detailed_analysis += f"\nHTTP: Methods used: {http.get('methods', {})}"
            detailed_analysis += f", {http.get('unique_user_agents', 0)} unique user agents"
        
        if proto_details.get('tls'):
            tls = proto_details['tls']
            detailed_analysis += f"\nTLS: {tls.get('unique_ja3', 0)} unique JA3 fingerprints"
            if tls.get('versions'):
                detailed_analysis += f", versions: {list(tls['versions'].keys())}"
        
        # Add TTP summary
        if ttps:
            ttp_list = [f"{t['technique_id']} ({t['technique_name']})" for t in ttps[:3]]
            detailed_analysis += f"\n\nNetwork-inferred TTPs: {', '.join(ttp_list)}"
        
        # Build conclusion with weighting
        current_weight = 0.75
        historical_weight = 0.25
        
        # Calculate scores
        current_score = min(1.0, total_sightings / 100) * 0.5 + min(1.0, len(protocols) / 3) * 0.5
        historical_score = threat_ratio if threat_ratio is not None else 0.5
        
        weighted_score = current_weight * current_score + historical_weight * historical_score
        
        if weighted_score > 0.6:
            assessment = "Threat-consistent"
            confidence_level = "high" if weighted_score > 0.75 else "medium"
        elif weighted_score < 0.4:
            assessment = "False-positive-consistent"
            confidence_level = "medium" if weighted_score > 0.25 else "high"
        else:
            assessment = "Inconclusive"
            confidence_level = "low"
        
        technical_conclusion = f"""Applying the 75%/25% weighting (current behavior / historical outcomes):

Current Window (75% weight): {total_sightings} sightings across {len(protocols)} protocols involving {distinct_src} source and {distinct_dst} destination IPs.

Historical Statistics (25% weight): This IOC has appeared in {hist_total} previous tickets, with {hist_tp} confirmed as Threat and {hist_fp} confirmed as False Positive (ratio: {f'{threat_ratio:.1%}' if threat_ratio is not None else 'N/A'}).

ASSESSMENT: {assessment}
CONFIDENCE: {confidence_level} ({weighted_score:.2f})

Key factors: {'Multi-protocol activity observed. ' if len(protocols) > 1 else ''}{'Historical threat ratio above 50%. ' if threat_ratio and threat_ratio > 0.5 else ''}{'Limited historical data. ' if hist_total < 3 else ''}
"""
        
        return LLMResponse(
            detailed_analysis=detailed_analysis,
            technical_conclusion=technical_conclusion,
            confidence_level=confidence_level,
            confidence_score=round(weighted_score, 2),
            success=True
        )


def generate_ai_analysis(aggregates: Dict[str, Any],
                         historical_stats: Dict[str, Any],
                         ttps: list,
                         ticket_info: Dict[str, Any],
                         config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to generate AI analysis.
    
    Args:
        aggregates: Zeek log aggregates
        historical_stats: Historical ticket statistics
        ttps: Detected TTPs
        ticket_info: Ticket metadata
        config: Optional LLM configuration
        
    Returns:
        Dictionary with analysis fields for JSON output
    """
    wrapper = CPUInferenceWrapper(config or {})
    response = wrapper.generate_analysis(aggregates, historical_stats, ttps, ticket_info)
    
    return {
        'detailed_communications_analysis': response.detailed_analysis,
        'technical_conclusion': response.technical_conclusion,
        'confidence': {
            'level': response.confidence_level,
            'score': response.confidence_score
        }
    }
