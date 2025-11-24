"""
Classification Diagnostic Tool

Run this to verify that the detection accuracy fixes are working correctly.
Shows detailed scoring breakdown for test columns.
"""
import sys
import os

# Add project root to path
_here = os.path.abspath(__file__)
_project_root = os.path.dirname(_here)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.services.ai_classification_pipeline_service import ai_classification_pipeline_service

def test_column_classification():
    """Test classification on known columns."""
    
    print("=" * 80)
    print("CLASSIFICATION DIAGNOSTIC TOOL")
    print("=" * 80)
    print()
    
    # Initialize service
    service = ai_classification_pipeline_service
    
    # Check if embeddings are initialized
    if not hasattr(service, '_embedder') or service._embedder is None:
        print("⚠️  Embeddings not initialized. Initializing now...")
        service._init_local_embeddings()
    
    # Check E5 model
    model_name = getattr(service._embedder, 'model_name', 'unknown') if service._embedder else 'none'
    is_e5 = 'e5' in str(model_name).lower()
    print(f"Model: {model_name}")
    print(f"Is E5: {is_e5}")
    print()
    
    # Test columns
    test_cases = [
        # PII columns
        ("CUSTOMER_EMAIL", "PII", "Should detect email pattern and PII keywords"),
        ("SSN", "PII", "Should detect SSN keyword"),
        ("PHONE_NUMBER", "PII", "Should detect phone keyword"),
        
        # SOX columns
        ("REVENUE_AMOUNT", "SOX", "Should detect financial keyword"),
        ("GL_ACCOUNT", "SOX", "Should detect accounting keyword"),
        ("INVOICE_TOTAL", "SOX", "Should detect financial keyword"),
        
        # SOC2 columns
        ("ACCESS_LOG", "SOC2", "Should detect security keyword"),
        ("AUDIT_TRAIL", "SOC2", "Should detect audit keyword"),
        ("USER_PERMISSION", "SOC2", "Should detect access control keyword"),
    ]
    
    print("=" * 80)
    print("TEST RESULTS")
    print("=" * 80)
    print()
    
    results = []
    
    for column_name, expected_category, reason in test_cases:
        print(f"Testing: {column_name}")
        print(f"  Expected: {expected_category}")
        print(f"  Reason: {reason}")
        
        # Get semantic scores
        if hasattr(service, '_semantic_scores'):
            scores = service._semantic_scores(column_name)
            
            if scores:
                # Find top category
                top_category = max(scores, key=scores.get)
                top_score = scores[top_category]
                
                # Check if correct
                is_correct = top_category.upper() == expected_category.upper()
                confidence_level = "HIGH" if top_score >= 0.90 else "MEDIUM" if top_score >= 0.70 else "LOW"
                
                # Display results
                print(f"  Result: {top_category} ({top_score:.2%})")
                print(f"  Confidence: {confidence_level}")
                print(f"  Status: {'✅ PASS' if is_correct else '❌ FAIL'}")
                
                # Show all scores
                print(f"  All scores:")
                for cat, score in sorted(scores.items(), key=lambda x: x[1], reverse=True):
                    print(f"    {cat}: {score:.2%}")
                
                results.append({
                    'column': column_name,
                    'expected': expected_category,
                    'actual': top_category,
                    'score': top_score,
                    'correct': is_correct,
                    'confidence': confidence_level
                })
            else:
                print(f"  Result: ❌ No scores returned")
                results.append({
                    'column': column_name,
                    'expected': expected_category,
                    'actual': 'NONE',
                    'score': 0.0,
                    'correct': False,
                    'confidence': 'NONE'
                })
        else:
            print(f"  Result: ❌ _semantic_scores method not found")
        
        print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print()
    
    total = len(results)
    correct = sum(1 for r in results if r['correct'])
    high_conf = sum(1 for r in results if r['confidence'] == 'HIGH')
    
    accuracy = (correct / total * 100) if total > 0 else 0
    high_conf_pct = (high_conf / total * 100) if total > 0 else 0
    
    print(f"Total Tests: {total}")
    print(f"Correct: {correct} ({accuracy:.1f}%)")
    print(f"High Confidence (90%+): {high_conf} ({high_conf_pct:.1f}%)")
    print()
    
    # Expected vs Actual
    print("Expected Results After Fixes:")
    print("  Accuracy: 90-100%")
    print("  High Confidence: 70-90%")
    print()
    
    if accuracy >= 90 and high_conf_pct >= 70:
        print("✅ FIXES ARE WORKING! Classification is accurate and confident.")
    elif accuracy >= 70:
        print("⚠️  PARTIAL SUCCESS. Accuracy is good but confidence may be low.")
        print("   Check that E5 prefixes are being applied correctly.")
    else:
        print("❌ FIXES NOT WORKING. Classification is still inaccurate.")
        print("   Possible issues:")
        print("   1. Embeddings not initialized")
        print("   2. E5 prefixes not being applied")
        print("   3. Category centroids not loaded")
        print("   4. Governance data not seeded")
    
    print()
    print("=" * 80)


if __name__ == "__main__":
    try:
        test_column_classification()
    except Exception as e:
        print(f"❌ Error running diagnostic: {e}")
        import traceback
        traceback.print_exc()
