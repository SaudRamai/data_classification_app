"""
Semantic Type Detector

Infers semantic types from data values and SQL types to provide
contextual hints for E5 embeddings.
"""
import re
from typing import List, Any, Optional


class SemanticTypeDetector:
    """Detects semantic types from sample values and SQL data types."""
    
    # Pattern definitions (compiled with re.IGNORECASE where applicable)
    EMAIL_PATTERN = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$', re.IGNORECASE)
    # Enhanced SSN pattern to match various formats including masked/obfuscated
    SSN_PATTERN = re.compile(r'^(\d{3}[- ]?\d{2}[- ]?\d{4}|XXX[- ]?XX[- ]?XXXX|###[- ]?##[- ]?####|\*{3}[- ]?\*{2}[- ]?\d{4}|SSN[#:;\s]*\d{3}[- ]?\d{2}[- ]?\d{4})$', re.IGNORECASE)
    PHONE_PATTERN = re.compile(r'^[\+\(]?[\d\s\-\(\)]{10,}$')
    CREDIT_CARD_PATTERN = re.compile(r'^\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}$')
    ZIP_PATTERN = re.compile(r'^\d{5}(-\d{4})?$')
    IP_ADDRESS_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    
    @staticmethod
    def infer_semantic_type(values: List[Any], data_type: str, column_name: str = "") -> str:
        """
        Infer semantic type from values, SQL type, and column name.
        
        Returns a human-readable semantic type hint for E5 embeddings.
        """
        if not values:
            return SemanticTypeDetector._type_from_sql(data_type, column_name)
        
        # Sample first 10 non-null values
        sample = [str(v).strip() for v in values[:10] if v is not None and str(v).strip()]
        if not sample:
            return SemanticTypeDetector._type_from_sql(data_type, column_name)
        
        # Pattern-based detection (high confidence)
        pattern_type = SemanticTypeDetector._detect_by_pattern(sample)
        if pattern_type:
            return pattern_type
        
        # SQL type + name heuristics
        return SemanticTypeDetector._type_from_sql(data_type, column_name)
    
    @staticmethod
    def _detect_by_pattern(sample: List[str]) -> Optional[str]:
        """Detect semantic type by matching patterns."""
        match_counts = {
            'email address': 0,
            'social security number': 0,
            'phone number': 0,
            'credit card number': 0,
            'postal code': 0,
            'ip address': 0,
            'unique identifier': 0,
        }
        
        for value in sample:
            if SemanticTypeDetector.EMAIL_PATTERN.match(value):
                match_counts['email address'] += 1
            elif SemanticTypeDetector.SSN_PATTERN.match(value):
                match_counts['social security number'] += 1
            elif SemanticTypeDetector.PHONE_PATTERN.match(value):
                match_counts['phone number'] += 1
            elif SemanticTypeDetector.CREDIT_CARD_PATTERN.match(value):
                match_counts['credit card number'] += 1
            elif SemanticTypeDetector.ZIP_PATTERN.match(value):
                match_counts['postal code'] += 1
            elif SemanticTypeDetector.IP_ADDRESS_PATTERN.match(value):
                match_counts['ip address'] += 1
            elif SemanticTypeDetector.UUID_PATTERN.match(value):
                match_counts['unique identifier'] += 1
        
        # Return type if >50% of samples match
        threshold = len(sample) * 0.5
        for type_name, count in match_counts.items():
            if count >= threshold:
                return type_name
        
        return None
    
    @staticmethod
    def _type_from_sql(data_type: str, column_name: str = "") -> str:
        """Infer semantic type from SQL data type and column name."""
        dt_upper = data_type.upper()
        cn_lower = column_name.lower()
        
        # Check for SSN in column name (case insensitive)
        if any(term in cn_lower for term in ['ssn', 'social', 'security', 'taxid', 'tax_id', 'taxid']):
            return 'social security number'
        
        # Date/Time types
        if any(t in dt_upper for t in ['DATE', 'TIME', 'TIMESTAMP']):
            if 'created' in cn_lower or 'modified' in cn_lower or 'updated' in cn_lower:
                return 'timestamp metadata'
            return 'date or timestamp'
        
        # Numeric types
        if any(t in dt_upper for t in ['DECIMAL', 'NUMERIC', 'FLOAT', 'DOUBLE']):
            if any(kw in cn_lower for kw in ['amount', 'price', 'cost', 'revenue', 'balance', 'salary']):
                return 'monetary amount'
            if any(kw in cn_lower for kw in ['percent', 'rate', 'ratio']):
                return 'percentage or rate'
            return 'numeric value'
        
        if any(t in dt_upper for t in ['INT', 'BIGINT', 'SMALLINT']):
            if 'id' in cn_lower or 'key' in cn_lower:
                return 'identifier or key'
            if any(kw in cn_lower for kw in ['count', 'quantity', 'number']):
                return 'count or quantity'
            return 'integer value'
        
        # String types
        if any(t in dt_upper for t in ['VARCHAR', 'CHAR', 'TEXT', 'STRING']):
            if 'email' in cn_lower:
                return 'email address'
            if 'phone' in cn_lower or 'mobile' in cn_lower:
                return 'phone number'
            if 'address' in cn_lower and 'email' not in cn_lower:
                return 'physical address'
            if 'name' in cn_lower:
                return 'person or entity name'
            if 'description' in cn_lower or 'comment' in cn_lower:
                return 'descriptive text'
            return 'text data'
        
        # Boolean
        if 'BOOL' in dt_upper:
            return 'boolean flag'
        
        # Binary
        if any(t in dt_upper for t in ['BINARY', 'BLOB', 'VARBINARY']):
            return 'binary data'
        
        return 'general data'


# Singleton instance
semantic_type_detector = SemanticTypeDetector()
