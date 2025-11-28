import sys
import os
import logging

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

# Mock dependencies if needed
import unittest.mock as mock
sys.modules['streamlit'] = mock.MagicMock()
sys.modules['src.connectors.snowflake_connector'] = mock.MagicMock()

from src.services.ai_classification_pipeline_service import ai_classification_pipeline_service

# Mock logger
logging.basicConfig(level=logging.INFO)

def test_tagging():
    service = ai_classification_pipeline_service
    
    print("Testing PII Tagging...")
    tags, reasoning = service._generate_governance_tags('PII_PERSONAL_INFO', 'PII')
    print(f"Tags: {tags}")
    print(f"Reasoning: {reasoning}")
    assert tags['DATA_CLASSIFICATION'] == 'Confidential'
    assert tags['CONFIDENTIALITY_LEVEL'] == 'C3'
    
    print("\nTesting SOX Tagging...")
    tags, reasoning = service._generate_governance_tags('SOX_FINANCIAL_DATA', 'SOX')
    print(f"Tags: {tags}")
    assert tags['REGULATORY_FRAMEWORK'] == 'SOX'
    assert tags['INTEGRITY_LEVEL'] == 'I3'
    
    print("\nTesting SOC2 Security Tagging...")
    tags, reasoning = service._generate_governance_tags('SOC2_SECURITY_DATA', 'SOC2')
    print(f"Tags: {tags}")
    assert tags['CONFIDENTIALITY_LEVEL'] == 'C2'
    
    print("\nTesting SOC2 Availability Tagging...")
    tags, reasoning = service._generate_governance_tags('SOC2_AVAILABILITY_DATA', 'SOC2')
    print(f"Tags: {tags}")
    assert tags['AVAILABILITY_LEVEL'] == 'A3'
    
    print("\nTesting Manual Overrides...")
    overrides = {'CONFIDENTIALITY_LEVEL': 'C1', 'NEW_TAG': 'Value'}
    tags, reasoning = service._generate_governance_tags('PII_PERSONAL_INFO', 'PII', overrides)
    print(f"Tags: {tags}")
    print(f"Reasoning: {reasoning}")
    assert tags['CONFIDENTIALITY_LEVEL'] == 'C1' # Override
    assert tags['INTEGRITY_LEVEL'] == 'I2' # Auto
    assert tags['NEW_TAG'] == 'Value'
    
    print("\nTesting Invalid Overrides...")
    overrides = {'CONFIDENTIALITY_LEVEL': 'C9'}
    tags, reasoning = service._generate_governance_tags('PII_PERSONAL_INFO', 'PII', overrides)
    print(f"Tags: {tags}")
    assert 'CONFIDENTIALITY_LEVEL' not in tags # Should be removed
    
    print("\nAll tests passed!")

if __name__ == "__main__":
    test_tagging()
