"""
LLM package for SecAI Reporter.
"""

from .cpu_inference import CPUInferenceWrapper, LLMResponse, generate_ai_analysis

__all__ = ['CPUInferenceWrapper', 'LLMResponse', 'generate_ai_analysis']
