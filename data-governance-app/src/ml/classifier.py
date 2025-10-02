"""
Machine Learning Classifier for Data Classification and Compliance Mapping.

This module implements a local machine learning approach for classifying data assets
and mapping them to compliance frameworks without using external APIs.
"""
import re
import pandas as pd
import numpy as np
from collections import Counter
from typing import Dict, List, Tuple, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
try:
    import streamlit as st  # optional; used for caching resource per session
except Exception:
    st = None


class DataComplianceClassifier:
    """
    A machine learning classifier for data assets that determines:
    1. Data classification level (Public, Internal, Restricted, Confidential)
    2. Applicable compliance frameworks (SOC 2, SOX, etc.)
    """
    
    def __init__(self):
        """Initialize the classifier with compliance rules and patterns."""
        # Define keywords for different compliance frameworks
        self.soc2_keywords = {
            'security', 'confidentiality', 'integrity', 'availability', 'protection',
            'access', 'authentication', 'authorization', 'monitoring', 'incident',
            'breach', 'vulnerability', 'penetration', 'audit', 'log'
        }
        
        self.sox_keywords = {
            'financial', 'accounting', 'transaction', 'revenue', 'expense',
            'asset', 'liability', 'equity', 'income', 'balance', 'ledger',
            'audit', 'control', 'reporting', 'sarbanes', 'disclosure'
        }
        
        self.pii_keywords = {
            'name', 'address', 'phone', 'email', 'ssn', 'social', 'security',
            'number', 'dob', 'birth', 'credit', 'card', 'bank', 'account',
            'passport', 'driver', 'license', 'medical', 'health', 'insurance'
        }
        
        # Classification level indicators
        self.public_indicators = {
            'public', 'general', 'overview', 'catalog', 'directory'
        }
        
        self.internal_indicators = {
            'internal', 'employee', 'department', 'team', 'project'
        }
        
        self.restricted_indicators = {
            'restricted', 'sensitive', 'proprietary', 'confidential',
            'private', 'limited', 'controlled'
        }
        
        self.confidential_indicators = {
            'confidential', 'secret', 'classified', 'top_secret',
            'password', 'credential', 'key', 'token'
        }
        
        # Column name patterns for PII detection
        self.pii_patterns = [
            r'.*name.*',
            r'.*address.*',
            r'.*phone.*',
            r'.*email.*',
            r'.*ssn.*',
            r'.*social.*security.*',
            r'.*dob.*',
            r'.*date.*birth.*',
            r'.*credit.*card.*',
            r'.*bank.*account.*',
            r'.*passport.*',
            r'.*driver.*license.*',
            r'.*medical.*',
            r'.*health.*',
            r'.*insurance.*',
            r'.*salary.*',
            r'.*compensation.*'
        ]
        
        # Financial data patterns
        self.financial_patterns = [
            r'.*revenue.*',
            r'.*profit.*',
            r'.*loss.*',
            r'.*asset.*',
            r'.*liability.*',
            r'.*equity.*',
            r'.*income.*',
            r'.*expense.*',
            r'.*transaction.*',
            r'.*account.*balance.*',
            r'.*ledger.*'
        ]
        
        # Initialize ML models
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize machine learning models for classification."""
        # For demonstration purposes, we'll create a simple rule-based model
        # In a production environment, you would train these models on labeled data
        self.classification_model = None
        self.framework_model = None
        
        # We'll use TF-IDF vectorizer for text features
        self.tfidf = TfidfVectorizer(max_features=100, stop_words='english')
    
    def extract_features(self, table_info: Dict[str, Any], sample_data: pd.DataFrame = None) -> Dict[str, Any]:
        """
        Extract features from table metadata and sample data.
        
        Args:
            table_info: Dictionary containing table metadata
            sample_data: Sample data from the table (optional)
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Extract features from table name and schema
        table_name = table_info.get('TABLE_NAME', '').lower()
        schema_name = table_info.get('TABLE_SCHEMA', '').lower()
        
        # Combine text features for TF-IDF
        text_features = f"{table_name} {schema_name}"
        
        # Name-based features
        features['table_name_length'] = len(table_name)
        features['schema_name_length'] = len(schema_name)
        
        # Keyword presence features
        features['soc2_keywords_in_name'] = sum(1 for kw in self.soc2_keywords if kw in table_name or kw in schema_name)
        features['sox_keywords_in_name'] = sum(1 for kw in self.sox_keywords if kw in table_name or kw in schema_name)
        features['pii_keywords_in_name'] = sum(1 for kw in self.pii_keywords if kw in table_name or kw in schema_name)
        
        # Classification indicators in names
        features['public_indicators'] = sum(1 for kw in self.public_indicators if kw in table_name or kw in schema_name)
        features['internal_indicators'] = sum(1 for kw in self.internal_indicators if kw in table_name or kw in schema_name)
        features['restricted_indicators'] = sum(1 for kw in self.restricted_indicators if kw in table_name or kw in schema_name)
        features['confidential_indicators'] = sum(1 for kw in self.confidential_indicators if kw in table_name or kw in schema_name)
        
        # Column-based features (if sample data is provided)
        if sample_data is not None and not sample_data.empty:
            column_names = [col.lower() for col in sample_data.columns]
            
            # PII column detection
            pii_columns = 0
            financial_columns = 0
            
            for col_name in column_names:
                # Check for PII patterns
                for pattern in self.pii_patterns:
                    if re.match(pattern, col_name, re.IGNORECASE):
                        pii_columns += 1
                        break
                
                # Check for financial patterns
                for pattern in self.financial_patterns:
                    if re.match(pattern, col_name, re.IGNORECASE):
                        financial_columns += 1
                        break
            
            features['pii_columns_ratio'] = pii_columns / len(column_names) if column_names else 0
            features['financial_columns_ratio'] = financial_columns / len(column_names) if column_names else 0
            features['total_columns'] = len(column_names)
            
            # Add sample data text to features
            sample_text = ' '.join([str(val) for row in sample_data.head(10).values for val in row if pd.notnull(val)])
            text_features += f" {sample_text}"
        else:
            features['pii_columns_ratio'] = 0
            features['financial_columns_ratio'] = 0
            features['total_columns'] = 0
        
        # Schema-based features
        features['is_prod_schema'] = 1 if 'prod' in schema_name else 0
        features['is_analytics_schema'] = 1 if 'analytic' in schema_name else 0
        features['is_financial_schema'] = 1 if any(kw in schema_name for kw in ['finance', 'accounting', 'financial']) else 0
        
        # Store text features for ML models
        features['text_features'] = text_features
        
        return features
    
    def classify_compliance_framework(self, features: Dict[str, Any]) -> List[str]:
        """
        Determine which compliance frameworks apply based on features.
        
        Args:
            features: Extracted features from the data asset
            
        Returns:
            List of applicable compliance frameworks
        """
        frameworks = []
        
        # SOC 2 determination
        soc2_score = features.get('soc2_keywords_in_name', 0) + features.get('restricted_indicators', 0)
        if soc2_score > 0:
            frameworks.append('SOC 2')
        
        # SOX determination
        sox_score = features.get('sox_keywords_in_name', 0) + features.get('financial_columns_ratio', 0) * 10
        if sox_score > 0.5 or features.get('is_financial_schema', 0) == 1:
            frameworks.append('SOX')
        
        # PII determination
        pii_score = features.get('pii_keywords_in_name', 0) + features.get('pii_columns_ratio', 0) * 10
        if pii_score > 0.3:
            frameworks.append('PII')
        
        return frameworks
    
    def classify_data_sensitivity(self, features: Dict[str, Any]) -> str:
        """
        Determine data classification level based on features.
        
        Args:
            features: Extracted features from the data asset
            
        Returns:
            Classification level (Public, Internal, Restricted, Confidential)
        """
        # Calculate scores for each classification level
        public_score = features.get('public_indicators', 0) * 2
        internal_score = features.get('internal_indicators', 0) * 2 + features.get('pii_columns_ratio', 0) * 3
        restricted_score = features.get('restricted_indicators', 0) * 2 + features.get('soc2_keywords_in_name', 0)
        confidential_score = features.get('confidential_indicators', 0) * 2 + features.get('pii_columns_ratio', 0) * 5
        
        # Adjust scores based on other factors
        if features.get('is_financial_schema', 0) == 1:
            confidential_score += 2
            
        if features.get('financial_columns_ratio', 0) > 0.3:
            confidential_score += 3
            
        if features.get('pii_columns_ratio', 0) > 0.5:
            confidential_score += 4
        
        # Determine classification based on highest score
        scores = {
            'Public': public_score,
            'Internal': internal_score,
            'Restricted': restricted_score,
            'Confidential': confidential_score
        }
        
        # Return the classification with the highest score
        return max(scores, key=scores.get)
    
    def classify_asset(self, table_info: Dict[str, Any], sample_data: pd.DataFrame = None) -> Dict[str, Any]:
        """
        Classify a data asset and determine applicable compliance frameworks.
        
        Args:
            table_info: Dictionary containing table metadata
            sample_data: Sample data from the table (optional)
            
        Returns:
            Dictionary containing classification results
        """
        # Extract features
        features = self.extract_features(table_info, sample_data)
        
        # Determine classification level
        classification = self.classify_data_sensitivity(features)
        
        # Determine applicable compliance frameworks
        frameworks = self.classify_compliance_framework(features)
        
        return {
            'classification': classification,
            'compliance_frameworks': frameworks,
            'features': features,
            'confidence': self._calculate_confidence(features)
        }
    
    def _calculate_confidence(self, features: Dict[str, Any]) -> float:
        """
        Calculate confidence score for the classification.
        
        Args:
            features: Extracted features
            
        Returns:
            Confidence score between 0 and 1
        """
        # Simple confidence calculation based on strength of indicators
        strong_indicators = (
            features.get('confidential_indicators', 0) +
            features.get('restricted_indicators', 0) +
            features.get('pii_columns_ratio', 0) * 5 +
            features.get('financial_columns_ratio', 0) * 5
        )
        
        # Normalize to 0-1 range (adjust multiplier as needed)
        confidence = min(1.0, strong_indicators / 10.0)
        return round(confidence, 2)


# Global instance (cached in Streamlit session when available)
if st is not None:
    @st.cache_resource(show_spinner=False)
    def _get_classifier_cached() -> DataComplianceClassifier:
        return DataComplianceClassifier()
    classifier = _get_classifier_cached()
else:
    classifier = DataComplianceClassifier()