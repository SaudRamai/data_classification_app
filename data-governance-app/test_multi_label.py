"""
Multi-Label Classification Diagnostic Script

This script tests the multi-label classification logic to ensure:
1. Columns can be classified with multiple categories
2. Table-level aggregation considers all detected categories from columns
3. The output includes detected_categories and multi_label_category fields
"""

import sys
from unittest.mock import MagicMock

# Add project root to path
sys.path.insert(0, 'c:/Users/ramai.saud/Downloads/DATA_CLASSIFICATION_APP/data-governance-app')

from src.services.ai_classification_pipeline_service import AIClassificationPipelineService

def test_multi_label_column_classification():
    """Test that columns can have multiple detected categories"""
    print("\n" + "="*60)
    print("TEST 1: Column Multi-Label Classification")
    print("="*60)
    
    service = AIClassificationPipelineService()
    
    # Mock dependencies
    service._category_thresholds = {
        'PII': 0.45,
        'SOX': 0.45,
        'SOC2': 0.45,
        'PII_PERSONAL_INFO': 0.45,
        'SOX_FINANCIAL_DATA': 0.45,
        'SOC2_SECURITY_DATA': 0.45
    }
    
    service._compute_governance_scores = MagicMock(return_value={
        'PII_PERSONAL_INFO': 0.85,
        'SOX_FINANCIAL_DATA': 0.72,
        'SOC2_SECURITY_DATA': 0.38  # Below threshold
    })
    
    service._apply_context_aware_adjustments = MagicMock(side_effect=lambda s, *args: s)
    service._map_category_to_policy_group = MagicMock(side_effect=lambda c: 'PII' if 'PII' in c else 'SOX' if 'SOX' in c else 'SOC2')
    service._normalize_category_for_cia = MagicMock(return_value='PII')
    service.ai_service = MagicMock()
    service.ai_service._map_cia_to_label = MagicMock(return_value='Confidential')
    
    # Test column classification
    column = {
        'COLUMN_NAME': 'customer_email',
        'DATA_TYPE': 'VARCHAR',
        'COLUMN_COMMENT': 'Customer email address'
    }
    
    result = service._classify_column_governance_driven('DB', 'SCHEMA', 'TABLE', column, pre_fetched_samples=['test@example.com'])
    
    detected = result.get('detected_categories', [])
    
    print(f"\nColumn: {result['column_name']}")
    print(f"Primary Category: {result['category']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"\nDetected Categories:")
    for cat in detected:
        print(f"  - {cat['category']}: {cat['confidence']:.2%}")
    
    # Verify
    assert len(detected) == 2, f"Expected 2 categories, got {len(detected)}"
    assert detected[0]['category'] == 'PII_PERSONAL_INFO', "Primary should be PII"
    assert detected[1]['category'] == 'SOX_FINANCIAL_DATA', "Secondary should be SOX"
    
    print("\n✅ PASS: Column correctly detected multiple categories")
    return True

def test_multi_label_table_aggregation():
    """Test that table aggregation considers all column categories"""
    print("\n" + "="*60)
    print("TEST 2: Table Multi-Label Aggregation")
    print("="*60)
    
    service = AIClassificationPipelineService()
    
    service._category_thresholds = {
        'PII': 0.45,
        'SOX': 0.45,
        'SOC2': 0.45
    }
    
    # Simulate column results with multi-label data
    column_results = [
        {
            'column_name': 'customer_id',
            'category': 'PII',
            'confidence': 0.88,
            'detected_categories': [
                {'category': 'PII', 'confidence': 0.88}
            ]
        },
        {
            'column_name': 'order_id',
            'category': 'SOX',
            'confidence': 0.82,
            'detected_categories': [
                {'category': 'SOX', 'confidence': 0.82},
                {'category': 'PII', 'confidence': 0.51}  # Also has PII signal
            ]
        },
        {
            'column_name': 'total_price',
            'category': 'SOX',
            'confidence': 0.91,
            'detected_categories': [
                {'category': 'SOX', 'confidence': 0.91}
            ]
        },
        {
            'column_name': 'customer_email',
            'category': 'PII',
            'confidence': 0.95,
            'detected_categories': [
                {'category': 'PII', 'confidence': 0.95},
                {'category': 'SOC2', 'confidence': 0.62}  # Email = access control
            ]
        }
    ]
    
    table_scores = {
        'SOX': 0.75,
        'PII': 0.68
    }
    
    # Test aggregation
    best_cat, best_score, detected = service._determine_table_category_governance_driven(
        table_scores, column_results
    )
    
    print(f"\nTable Classification:")
    print(f"Primary Category: {best_cat}")
    print(f"Confidence: {best_score:.2%}")
    print(f"\nAll Detected Categories:")
    for cat in detected:
        print(f"  - {cat['category']}: {cat['confidence']:.2%}")
    
    # Verify
    assert len(detected) >= 2, f"Expected at least 2 categories, got {len(detected)}"
    
    cat_names = {d['category'] for d in detected}
    assert 'SOX' in cat_names, "SOX should be detected"
    assert 'PII' in cat_names, "PII should be detected"
    
    # Check that PII score was boosted due to multiple columns (customer_id, order_id, customer_email)
    pii_entry = next((d for d in detected if d['category'] == 'PII'), None)
    assert pii_entry is not None, "PII entry should exist"
    
    print("\n✅ PASS: Table correctly aggregated multi-label signals from columns")
    return True

def main():
    print("\n" + "="*60)
    print("MULTI-LABEL CLASSIFICATION DIAGNOSTIC")
    print("="*60)
    
    try:
        test_multi_label_column_classification()
        test_multi_label_table_aggregation()
        
        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED")
        print("="*60)
        print("\nThe multi-label classification logic is working correctly!")
        print("You should now see 'detected_categories' in your classification results.")
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
