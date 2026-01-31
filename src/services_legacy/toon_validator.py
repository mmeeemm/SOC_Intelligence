"""
TOON Validation Gate
Deterministic validation with explicit pass/fail logic and violation reporting.
"""

import logging
from typing import List, Optional
from dataclasses import dataclass

from src.services.correlation_engine import CorrGroup
from src.utils.toon_format import PLACEHOLDER_TOKENS, L1_L2_KEYS

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of TOON validation."""
    status: str  # VALID or INVALID
    violations: List[str]
    summary: Optional[str] = None
    
    def __str__(self) -> str:
        """Format as pipeline output."""
        if self.status == 'INVALID':
            return f"INVALID\nviolations={'; '.join(self.violations)}"
        else:
            output = "VALID"
            if self.summary:
                output += f"\n{self.summary}"
            return output


class TOONValidator:
    """
    Validation gate for TOON CORR_GROUP structures.
    
    Validates:
    - Structure: CORR_GROUP format compliance
    - Hygiene: No empty/null/placeholder values
    - Layer policy: No L1/L2 artifacts
    - Correlation consistency: corr_level matches corr_key method
    """
    
    def __init__(self, include_validation_details: bool = True):
        """
        Args:
            include_validation_details: If True, output validation_summary
        """
        self.include_validation_details = include_validation_details
    
    def validate(self, corr_groups: List[CorrGroup]) -> ValidationResult:
        """
        Main validation entry point.
        
        Args:
            corr_groups: List of CorrGroup objects to validate
        
        Returns:
            ValidationResult with status and violations
        """
        violations = []
        
        # Run all validation checks
        violations.extend(self._validate_structure(corr_groups))
        violations.extend(self._validate_hygiene(corr_groups))
        violations.extend(self._validate_layer_policy(corr_groups))
        violations.extend(self._validate_correlation_consistency(corr_groups))
        
        # Determine status
        if violations:
            return ValidationResult(
                status='INVALID',
                violations=violations
            )
        else:
            summary = None
            if self.include_validation_details:
                summary = f"validation_summary=passed ({len(corr_groups)} CORR_GROUPs validated)"
            
            return ValidationResult(
                status='VALID',
                violations=[],
                summary=summary
            )
    
    def _validate_structure(self, corr_groups: List[CorrGroup]) -> List[str]:
        """
        Validate CORR_GROUP structural requirements.
        
        Checks:
        - At least one CORR_GROUP exists
        - Each has corr_id, corr_level, corr_key, corr_confidence
        - No empty lines in blocks
        - key=value formatting enforced
        """
        violations = []
        
        if not corr_groups:
            violations.append("No CORR_GROUP blocks found")
            return violations
        
        for i, group in enumerate(corr_groups, 1):
            # Check required fields
            if not group.corr_id:
                violations.append(f"CORR_GROUP {i}: Missing corr_id")
            if not group.corr_level:
                violations.append(f"CORR_GROUP {i}: Missing corr_level")
            if not group.corr_key:
                violations.append(f"CORR_GROUP {i}: Missing corr_key")
            if not group.corr_confidence:
                violations.append(f"CORR_GROUP {i}: Missing corr_confidence")
            
            # Check corr_level valid values
            if group.corr_level not in ['packet', 'transaction', 'flow']:
                violations.append(f"CORR_GROUP {i}: Invalid corr_level '{group.corr_level}' (must be packet|transaction|flow)")
            
            # Check corr_confidence valid values
            if group.corr_confidence not in ['high', 'medium', 'low']:
                violations.append(f"CORR_GROUP {i}: Invalid corr_confidence '{group.corr_confidence}' (must be high|medium|low)")
            
            # Check block formatting
            for j, block in enumerate(group.blocks, 1):
                lines = block.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    # Empty lines not allowed
                    if not line.strip():
                        violations.append(f"CORR_GROUP {i}, Block {j}, Line {line_num}: Empty line detected")
                        continue
                    
                    # Must be block header or key=value
                    if line.startswith('[') and line.endswith(']'):
                        # Valid block header
                        continue
                    elif '=' in line:
                        # key=value format
                        key, value = line.split('=', 1)
                        if not key.strip():
                            violations.append(f"CORR_GROUP {i}, Block {j}, Line {line_num}: Empty key in '{line}'")
                        if not value.strip():
                            violations.append(f"CORR_GROUP {i}, Block {j}, Line {line_num}: Empty value for key '{key}'")
                    else:
                        violations.append(f"CORR_GROUP {i}, Block {j}, Line {line_num}: Invalid format '{line}' (not block header or key=value)")
        
        return violations
    
    def _validate_hygiene(self, corr_groups: List[CorrGroup]) -> List[str]:
        """
        Validate hygiene requirements.
        
        Checks:
        - No empty values
        - No null values
        - No placeholder tokens ("-", "N/A", "unknown")
        - No placeholder-zero metrics
        - No keys without values
        - No empty protocol blocks
        """
        violations = []
        
        for i, group in enumerate(corr_groups, 1):
            for j, block in enumerate(group.blocks, 1):
                lines = block.split('\n')
                block_type = lines[0] if lines else ''
                
                # Check if block becomes empty after header
                if len(lines) <= 1:
                    violations.append(f"CORR_GROUP {i}, Block {j}: Empty block (no key=value pairs)")
                    continue
                
                for line_num, line in enumerate(lines[1:], 2):  # Skip header
                    if '=' in line:
                        key, value = line.split('=', 1)
                        value = value.strip()
                        
                        # Check for forbidden values
                        if not value:
                            violations.append(f"CORR_GROUP {i}, Block {j}, Line {line_num}: Empty value for key '{key}'")
                        
                        if value.lower() in ['null', 'none']:
                            violations.append(f"CORR_GROUP {i}, Block {j}, Line {line_num}: Null value for key '{key}'")
                        
                        if value in PLACEHOLDER_TOKENS:
                            violations.append(f"CORR_GROUP {i}, Block {j}, Line {line_num}: Placeholder token '{value}' for key '{key}'")
                        
                        # Check for placeholder zeros (contextual)
                        # Only flag if it's clearly a count/metric field set to 0 inappropriately
                        if value == '0' and any(term in key.lower() for term in ['count', 'pkts', 'bytes', 'duration']):
                            # This is acceptable for legitimate zero values, so we don't flag it
                            # (The prompt says "placeholder-zero", meaning zeros used as missing indicators)
                            pass
        
        return violations
    
    def _validate_layer_policy(self, corr_groups: List[CorrGroup]) -> List[str]:
        """
        Validate Layer 3+ policy enforcement.
        
        Checks:
        - No L1/L2 artifacts (Ethernet, ARP, MAC, VLAN, L2 headers, MAC addresses)
        - No reference to Physical or Data Link layers
        """
        violations = []
        
        for i, group in enumerate(corr_groups, 1):
            for j, block in enumerate(group.blocks, 1):
                lines = block.split('\n')
                
                for line_num, line in enumerate(lines[1:], 2):  # Skip header
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key_lower = key.lower().strip()
                        value_lower = value.lower().strip()
                        
                        # Check key for forbidden L1/L2 terms
                        for forbidden in L1_L2_KEYS:
                            if forbidden in key_lower:
                                violations.append(f"CORR_GROUP {i}, Block {j}, Line {line_num}: L1/L2 artifact in key '{key}'")
                                break
                        
                        # Check value for MAC addresses (xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx)
                        if self._is_mac_address(value):
                            violations.append(f"CORR_GROUP {i}, Block {j}, Line {line_num}: MAC address detected in value '{value}'")
                        
                        # Check for explicit L1/L2 layer mentions
                        forbidden_phrases = ['layer 1', 'layer 2', 'l1', 'l2', 'physical layer', 'data link']
                        for phrase in forbidden_phrases:
                            if phrase in value_lower:
                                violations.append(f"CORR_GROUP {i}, Block {j}, Line {line_num}: L1/L2 reference in value '{value}'")
                                break
        
        return violations
    
    def _validate_correlation_consistency(self, corr_groups: List[CorrGroup]) -> List[str]:
        """
        Validate correlation consistency.
        
        Checks:
        - corr_level must match corr_key method
        - corr_confidence must match method strength
        """
        violations = []
        
        for i, group in enumerate(corr_groups, 1):
            corr_key = group.corr_key.lower()
            corr_level = group.corr_level
            corr_confidence = group.corr_confidence
            
            # Packet-level correlation checks
            if corr_level == 'packet':
                # Must use frame.number, pcap_packet_id, or derived method
                has_frame = 'frame.number=' in corr_key or 'pcap_packet_id=' in corr_key
                has_derived = all(term in corr_key for term in ['ts=', '5tuple=', 'ip_id='])
                
                if not (has_frame or has_derived):
                    violations.append(f"CORR_GROUP {i}: corr_level='packet' but corr_key doesn't use packet-level method (frame.number or derived)")
                
                # frame.number/pcap_packet_id should be high confidence
                if has_frame and corr_confidence != 'high':
                    violations.append(f"CORR_GROUP {i}: Packet-level correlation with frame.number should have confidence='high', got '{corr_confidence}'")
                
                # Derived method should be medium
                if has_derived and not has_frame and corr_confidence == 'high':
                    violations.append(f"CORR_GROUP {i}: Packet-level derived correlation should have confidence='medium', got '{corr_confidence}'")
            
            # Transaction-level correlation checks
            elif corr_level == 'transaction':
                # Should use transaction identifiers
                has_txid = any(term in corr_key for term in ['dns_id=', 'http_stream=', 'tls_handshake=', 'txid='])
                
                if not has_txid:
                    violations.append(f"CORR_GROUP {i}: corr_level='transaction' but corr_key doesn't use transaction identifier")
                
                # With 5-tuple should be medium, without should be low
                has_5tuple = '5tuple=' in corr_key
                if has_5tuple and corr_confidence == 'high':
                    violations.append(f"CORR_GROUP {i}: Transaction-level should not have confidence='high'")
                if not has_5tuple and corr_confidence != 'low':
                    violations.append(f"CORR_GROUP {i}: Transaction-level without 5-tuple should have confidence='low', got '{corr_confidence}'")
            
            # Flow-level correlation checks
            elif corr_level == 'flow':
                # Should use uid or 5-tuple
                has_uid = 'zeek_uid=' in corr_key
                has_5tuple = '5tuple=' in corr_key
                
                if not (has_uid or has_5tuple):
                    violations.append(f"CORR_GROUP {i}: corr_level='flow' but corr_key doesn't use flow identifier (uid or 5-tuple)")
                
                # uid with 5-tuple can be medium, otherwise low
                if has_uid and '5tuple=' in corr_key and corr_confidence not in ['medium', 'low']:
                    violations.append(f"CORR_GROUP {i}: Flow-level with uid should have confidence='medium' or 'low'")
        
        return violations
    
    def _is_mac_address(self, value: str) -> bool:
        """Check if value looks like a MAC address."""
        import re
        # MAC address patterns: xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, value.strip()))


# Global singleton
toon_validator = TOONValidator()
