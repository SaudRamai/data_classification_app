"""
Tests for the AI-Sensitive Detection Service.
"""
import unittest
from unittest.mock import MagicMock, patch
from typing import List, Dict, Any

from src.services.ai_sensitive_detection_service import (
    AISensitiveDetectionService,
    DetectionResult
)

class TestAISensitiveDetectionService(unittest.TestCase):
    """Test cases for AI-Sensitive Detection Service."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.service = AISensitiveDetectionService(sample_size=5, use_ai=False)
        
        # Mock Snowflake connector
        self.mock_connector = MagicMock()
        self.original_connector = None
        
        # Sample data for tests
        self.sample_metadata = [
            {
                'table_schema': 'HR',
                'table_name': 'EMPLOYEES',
                'column_name': 'SSN',
                'data_type': 'VARCHAR',
                'column_comment': 'Social Security Number'
            },
            {
                'table_schema': 'HR',
                'table_name': 'EMPLOYEES',
                'column_name': 'EMAIL',
                'data_type': 'VARCHAR',
                'column_comment': 'Work email address'
            },
            {
                'table_schema': 'SALES',
                'table_name': 'CUSTOMERS',
                'column_name': 'CREDIT_CARD',
                'data_type': 'VARCHAR',
                'column_comment': 'Encrypted credit card number'
            },
            {
                'table_schema': 'SALES',
                'table_name': 'CUSTOMERS',
                'column_name': 'NAME',
                'data_type': 'VARCHAR',
                'column_comment': 'Customer full name'
            },
        ]
        
        # Sample data for pattern matching
        self.sample_data = {
            'HR.EMPLOYEES.SSN': ['123-45-6789', '987-65-4321', '456-78-9012'],
            'HR.EMPLOYEES.EMAIL': ['john.doe@example.com', 'jane.smith@example.com'],
            'SALES.CUSTOMERS.CREDIT_CARD': ['4111-1111-1111-1111', '5500-0000-0000-0004'],
            'SALES.CUSTOMERS.NAME': ['John Doe', 'Jane Smith']
        }
        
        # Patch the Snowflake connector
        self.original_connector = self.service.detector.snowflake_connector
        self.service.detector.snowflake_connector = self.mock_connector
        
        # Mock the base detector's methods
        self.service.detector._check_keyword_matches = MagicMock(side_effect=self._mock_check_keyword_matches)
        self.service.detector._check_pattern_matches = MagicMock(side_effect=self._mock_check_pattern_matches)
    
    def tearDown(self):
        """Clean up after tests."""
        # Restore original connector
        if self.original_connector:
            self.service.detector.snowflake_connector = self.original_connector
    
    def _mock_check_keyword_matches(self, text: str) -> List[Dict]:
        """Mock keyword matching."""
        text = text.upper()
        matches = []
        
        if 'SSN' in text or 'SOCIAL' in text or 'SECURITY' in text:
            matches.append({
                'keyword_id': 'SSN_KW',
                'keyword_string': 'SSN',
                'category_id': 'PII',
                'category_name': 'PII',
                'weight': 0.9
            })
        
        if 'EMAIL' in text or 'E_MAIL' in text:
            matches.append({
                'keyword_id': 'EMAIL_KW',
                'keyword_string': 'EMAIL',
                'category_id': 'PII',
                'category_name': 'PII',
                'weight': 0.8
            })
            
        if 'CREDIT' in text and 'CARD' in text:
            matches.append({
                'keyword_id': 'CC_KW',
                'keyword_string': 'CREDIT_CARD',
                'category_id': 'FINANCIAL',
                'category_name': 'FINANCIAL',
                'weight': 1.0
            })
            
        if 'NAME' in text and 'FIRST' not in text and 'LAST' not in text:
            matches.append({
                'keyword_id': 'NAME_KW',
                'keyword_string': 'NAME',
                'category_id': 'PII',
                'category_name': 'PII',
                'weight': 0.6
            })
            
        return matches
    
    def _mock_check_pattern_matches(self, text: str) -> List[Dict]:
        """Mock pattern matching."""
        import re
        matches = []
        
        # SSN pattern
        ssn_pattern = r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b'
        if re.search(ssn_pattern, text):
            matches.append({
                'pattern_id': 'SSN_PAT',
                'pattern_string': ssn_pattern,
                'category_id': 'PII',
                'category_name': 'PII',
                'weight': 0.95
            })
        
        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if re.search(email_pattern, text, re.IGNORECASE):
            matches.append({
                'pattern_id': 'EMAIL_PAT',
                'pattern_string': email_pattern,
                'category_id': 'PII',
                'category_name': 'PII',
                'weight': 0.9
            })
            
        # Credit card pattern (simplified)
        cc_pattern = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b'
        if re.search(cc_pattern, text.replace('-', '')):
            matches.append({
                'pattern_id': 'CC_PAT',
                'pattern_string': cc_pattern,
                'category_id': 'FINANCIAL',
                'category_name': 'FINANCIAL',
                'weight': 1.0
            })
            
        return matches
    
    def test_discover_metadata(self):
        """Test metadata discovery."""
        # Mock the Snowflake connector response
        self.mock_connector.execute_query.return_value = self.sample_metadata
        
        # Test with no filters
        results = self.service.discover_metadata('TEST_DB')
        self.assertEqual(len(results), 4)
        self.assertEqual(results[0]['table_schema'], 'HR')
        self.assertEqual(results[0]['table_name'], 'EMPLOYEES')
        
        # Test with schema filter
        results = self.service.discover_metadata('TEST_DB', schema_name='HR')
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r['table_schema'] == 'HR' for r in results))
        
        # Test with table filter
        results = self.service.discover_metadata('TEST_DB', table_name='CUSTOMERS')
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r['table_name'] == 'CUSTOMERS' for r in results))
    
    def test_detect_sensitive_columns(self):
        """Test sensitive column detection."""
        # Mock the Snowflake connector for metadata
        self.mock_connector.execute_query.side_effect = [
            self.sample_metadata,  # First call for metadata
            [{'SAMPLE_VALUE': '123-45-6789'}, {'SAMPLE_VALUE': '987-65-4321'}]  # Sample data for SSN
        ]
        
        # Test detection for a specific column
        results = self.service.detect_sensitive_columns(
            'TEST_DB', 
            schema_name='HR', 
            table_name='EMPLOYEES',
            column_name='SSN'
        )
        
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.column_name, 'SSN')
        self.assertEqual(result.schema_name, 'HR')
        self.assertEqual(result.table_name, 'EMPLOYEES')
        self.assertGreaterEqual(result.confidence, 0.7)  # Should be high confidence for SSN
        self.assertIn('PII', result.detected_categories)
    
    def test_detect_sensitive_tables(self):
        """Test table-level sensitivity detection."""
        # Mock the Snowflake connector for metadata and sample data
        self.mock_connector.execute_query.side_effect = [
            self.sample_metadata,  # First call for metadata
            [{'SAMPLE_VALUE': '123-45-6789'}],  # SSN sample
            [{'SAMPLE_VALUE': 'john.doe@example.com'}],  # Email sample
            [{'SAMPLE_VALUE': '4111-1111-1111-1111'}],  # Credit card sample
            [{'SAMPLE_VALUE': 'John Doe'}]  # Name sample
        ]
        
        # Test table detection
        results = self.service.detect_sensitive_tables('TEST_DB')
        
        # Should find both tables
        self.assertEqual(len(results), 2)
        
        # Check HR.EMPLOYEES table
        hr_table = next(t for t in results if t['table'] == 'EMPLOYEES')
        self.assertEqual(hr_table['sensitivity_level'], 'HIGH')
        self.assertEqual(len(hr_table['sensitive_columns']), 2)
        
        # Check SALES.CUSTOMERS table
        sales_table = next(t for t in results if t['table'] == 'CUSTOMERS')
        self.assertEqual(sales_table['sensitivity_level'], 'HIGH')
        self.assertEqual(len(sales_table['sensitive_columns']), 2)
    
    def test_calculate_final_scores(self):
        """Test confidence and sensitivity score calculation."""
        # Create a test result
        result = DetectionResult(
            database_name='TEST_DB',
            schema_name='HR',
            table_name='EMPLOYEES',
            column_name='SSN',
            data_type='VARCHAR',
            keyword_matches=[{
                'keyword_id': 'SSN_KW',
                'keyword_string': 'SSN',
                'category_id': 'PII',
                'category_name': 'PII',
                'weight': 90
            }],
            pattern_matches=[{
                'pattern_id': 'SSN_PAT',
                'pattern_string': '\\d{3}-\\d{2}-\\d{4}',
                'category_id': 'PII',
                'category_name': 'PII',
                'weight': 95
            }],
            sample_values=['123-45-6789', '987-65-4321']
        )
        
        # Calculate scores
        self.service._calculate_final_scores(result)
        
        # Verify results
        self.assertGreaterEqual(result.confidence, 0.9)  # Should be high confidence
        self.assertEqual(result.sensitivity_level, 'HIGH')
        self.assertIn('PII', result.detected_categories)
        self.assertIn('KEYWORD_MATCH', result.detection_methods)
        self.assertIn('PATTERN_MATCH', result.detection_methods)

if __name__ == '__main__':
    unittest.main()
