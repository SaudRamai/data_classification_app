"""
Test script for AI Classification System
"""
import pandas as pd
from src.ml.classifier import classifier
from src.services.ai_classification_service import ai_classification_service

def test_classifier():
    """Test the classifier with sample data"""
    print("Testing AI Classification System...")
    
    # Test feature extraction
    table_info = {
        'TABLE_NAME': 'EMPLOYEE_SALARY',
        'TABLE_SCHEMA': 'HR',
        'TABLE_CATALOG': 'PILOT_DB'
    }
    
    # Create sample data with PII columns
    sample_data = pd.DataFrame({
        'employee_id': [1, 2, 3],
        'name': ['John Doe', 'Jane Smith', 'Bob Johnson'],
        'ssn': ['123-45-6789', '987-65-4321', '555-55-5555'],
        'salary': [50000, 60000, 55000],
        'email': ['john@company.com', 'jane@company.com', 'bob@company.com']
    })
    
    # Test feature extraction
    features = classifier.extract_features(table_info, sample_data)
    print("\nExtracted Features:")
    for key, value in features.items():
        if key != 'text_features':  # Skip text features for brevity
            print(f"  {key}: {value}")
    
    # Test classification
    result = classifier.classify_asset(table_info, sample_data)
    print("\nClassification Result:")
    print(f"  Classification: {result['classification']}")
    print(f"  Compliance Frameworks: {result['compliance_frameworks']}")
    print(f"  Confidence: {result['confidence']}")
    
    print("\nAI Classification System Test Complete!")

if __name__ == "__main__":
    test_classifier()