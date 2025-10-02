"""
Test script for AI Classification System Fixes
"""
import pandas as pd
from src.services.ai_classification_service import ai_classification_service

def test_ai_service():
    """Test the AI classification service with sample data"""
    print("Testing AI Classification Service Fixes...")
    
    # Test table metadata extraction
    try:
        # Use a simple table name that should exist in the pilot database
        table_info = ai_classification_service.get_table_metadata("PILOT_DB.INFORMATION_SCHEMA.TABLES")
        print("\nTable Metadata Extraction: SUCCESS")
        print(f"  Table: {table_info.get('TABLE_NAME', 'N/A')}")
        print(f"  Schema: {table_info.get('TABLE_SCHEMA', 'N/A')}")
    except Exception as e:
        print(f"\nTable Metadata Extraction: FAILED - {e}")
    
    # Test column metadata extraction
    try:
        columns = ai_classification_service.get_column_metadata("PILOT_DB.INFORMATION_SCHEMA.TABLES")
        print("\nColumn Metadata Extraction: SUCCESS")
        print(f"  Number of columns: {len(columns)}")
        if columns:
            print(f"  First column: {columns[0].get('COLUMN_NAME', 'N/A')}")
    except Exception as e:
        print(f"\nColumn Metadata Extraction: FAILED - {e}")
    
    # Test sample data extraction
    try:
        sample_data = ai_classification_service.get_sample_data("PILOT_DB.INFORMATION_SCHEMA.TABLES", 5)
        print("\nSample Data Extraction: SUCCESS")
        print(f"  Shape: {sample_data.shape}")
    except Exception as e:
        print(f"\nSample Data Extraction: FAILED - {e}")
    
    print("\nAI Classification Service Fixes Test Complete!")

if __name__ == "__main__":
    test_ai_service()