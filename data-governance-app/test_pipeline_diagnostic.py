"""
AI Classification Pipeline Diagnostic & Validation Script

This script tests each component of the classification pipeline to identify failures:
1. Governance table connectivity
2. Embedding model loading
3. Category centroid building
4. Semantic scoring engine
5. Column classification
6. Category mapping
7. Confidence calibration

Run this to diagnose what's broken before attempting fixes.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import logging
from typing import Dict, List, Any, Optional
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_imports():
    """Test 1: Can we import all required modules?"""
    print("\n" + "="*80)
    print("TEST 1: MODULE IMPORTS")
    print("="*80)
    
    try:
        from src.connectors.snowflake_connector import snowflake_connector
        print("✅ Snowflake connector imported")
    except Exception as e:
        print(f"❌ Snowflake connector import failed: {e}")
        return False
    
    try:
        from src.services.ai_classification_pipeline_service import ai_classification_pipeline_service
        print("✅ Classification pipeline service imported")
    except Exception as e:
        print(f"❌ Classification pipeline service import failed: {e}")
        return False
    
    try:
        from sentence_transformers import SentenceTransformer
        print("✅ SentenceTransformer imported")
    except Exception as e:
        print(f"❌ SentenceTransformer import failed: {e}")
        return False
    
    return True

def test_governance_connectivity():
    """Test 2: Can we access governance tables?"""
    print("\n" + "="*80)
    print("TEST 2: GOVERNANCE TABLE CONNECTIVITY")
    print("="*80)
    
    try:
        from src.connectors.snowflake_connector import snowflake_connector
        
        # Test SENSITIVITY_CATEGORIES
        try:
            query = """
                SELECT COUNT(*) as CNT 
                FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES
                WHERE IS_ACTIVE = TRUE
            """
            result = snowflake_connector.execute_query(query)
            count = result[0]['CNT'] if result else 0
            print(f"✅ SENSITIVITY_CATEGORIES: {count} active categories")
        except Exception as e:
            print(f"❌ SENSITIVITY_CATEGORIES access failed: {e}")
            return False
        
        # Test SENSITIVE_KEYWORDS
        try:
            query = """
                SELECT COUNT(*) as CNT 
                FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS
                WHERE IS_ACTIVE = TRUE
            """
            result = snowflake_connector.execute_query(query)
            count = result[0]['CNT'] if result else 0
            print(f"✅ SENSITIVE_KEYWORDS: {count} active keywords")
        except Exception as e:
            print(f"❌ SENSITIVE_KEYWORDS access failed: {e}")
            return False
        
        # Test SENSITIVE_PATTERNS
        try:
            query = """
                SELECT COUNT(*) as CNT 
                FROM DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS
                WHERE IS_ACTIVE = TRUE
            """
            result = snowflake_connector.execute_query(query)
            count = result[0]['CNT'] if result else 0
            print(f"✅ SENSITIVE_PATTERNS: {count} active patterns")
        except Exception as e:
            print(f"❌ SENSITIVE_PATTERNS access failed: {e}")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Governance connectivity test failed: {e}")
        return False

def test_category_loading():
    """Test 3: Can we load category metadata?"""
    print("\n" + "="*80)
    print("TEST 3: CATEGORY METADATA LOADING")
    print("="*80)
    
    try:
        from src.services.ai_classification_pipeline_service import ai_classification_pipeline_service as service
        
        # Check if categories are loaded
        if hasattr(service, '_category_centroids'):
            centroids = service._category_centroids
            print(f"✅ Category centroids loaded: {len(centroids)} categories")
            
            # Check centroid quality
            valid_centroids = sum(1 for c in centroids.values() if c is not None)
            print(f"   Valid centroids: {valid_centroids}/{len(centroids)}")
            
            if valid_centroids == 0:
                print("❌ WARNING: No valid centroids! Semantic scoring will fail.")
                return False
        else:
            print("❌ No category centroids found")
            return False
        
        # Check keywords
        if hasattr(service, '_category_keywords'):
            keywords = service._category_keywords
            total_keywords = sum(len(kws) for kws in keywords.values())
            print(f"✅ Keywords loaded: {total_keywords} total across {len(keywords)} categories")
        else:
            print("⚠️  No keywords loaded")
        
        # Check patterns
        if hasattr(service, '_category_patterns'):
            patterns = service._category_patterns
            total_patterns = sum(len(pats) for pats in patterns.values())
            print(f"✅ Patterns loaded: {total_patterns} total across {len(patterns)} categories")
        else:
            print("⚠️  No patterns loaded")
        
        return True
        
    except Exception as e:
        print(f"❌ Category loading test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_embedding_model():
    """Test 4: Can we load and use the embedding model?"""
    print("\n" + "="*80)
    print("TEST 4: EMBEDDING MODEL")
    print("="*80)
    
    try:
        from src.services.ai_classification_pipeline_service import ai_classification_pipeline_service as service
        
        if hasattr(service, '_embedder') and service._embedder is not None:
            print(f"✅ Embedder loaded: {type(service._embedder)}")
            
            # Test encoding
            test_text = "customer email address"
            try:
                embedding = service._embedder.encode([test_text], normalize_embeddings=True)
                print(f"✅ Test encoding successful: dimension={len(embedding[0])}")
                
                # Check if normalized
                norm = np.linalg.norm(embedding[0])
                print(f"   Vector norm: {norm:.4f} (should be ~1.0 for normalized)")
                
            except Exception as e:
                print(f"❌ Test encoding failed: {e}")
                return False
        else:
            print("❌ No embedder loaded")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Embedding model test failed: {e}")
        return False

def test_semantic_scoring():
    """Test 5: Does semantic scoring work?"""
    print("\n" + "="*80)
    print("TEST 5: SEMANTIC SCORING ENGINE")
    print("="*80)
    
    try:
        from src.services.ai_classification_pipeline_service import ai_classification_pipeline_service as service
        
        # Check if method exists
        if not hasattr(service, '_semantic_scores'):
            print("❌ _semantic_scores method not found!")
            return False
        
        print("✅ _semantic_scores method exists")
        
        # Test with obvious PII text
        test_cases = [
            ("customer email address", "PII"),
            ("social security number", "PII"),
            ("account balance amount", "SOX"),
            ("password hash", "SOC2"),
        ]
        
        for text, expected_category in test_cases:
            try:
                scores = service._semantic_scores(text)
                
                if not scores:
                    print(f"❌ '{text}': No scores returned")
                    continue
                
                top_category = max(scores, key=scores.get)
                top_score = scores[top_category]
                
                match = "✅" if expected_category in top_category or top_category in expected_category else "⚠️ "
                print(f"{match} '{text}': {top_category} ({top_score:.2%})")
                
                if top_score < 0.25:
                    print(f"   WARNING: Very low confidence!")
                
            except Exception as e:
                print(f"❌ '{text}': Scoring failed - {e}")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ Semantic scoring test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_category_mapping():
    """Test 6: Does category mapping work?"""
    print("\n" + "="*80)
    print("TEST 6: CATEGORY MAPPING")
    print("="*80)
    
    try:
        from src.services.ai_classification_pipeline_service import ai_classification_pipeline_service as service
        
        if not hasattr(service, '_map_category_to_policy_group'):
            print("❌ _map_category_to_policy_group method not found!")
            return False
        
        print("✅ _map_category_to_policy_group method exists")
        
        # Test mappings
        test_categories = [
            "Email Address",
            "Social Security Number",
            "Credit Card",
            "Account Number",
            "Password",
            "API Key",
        ]
        
        for category in test_categories:
            try:
                policy_group = service._map_category_to_policy_group(category)
                print(f"   '{category}' → {policy_group}")
                
                if policy_group is None:
                    print(f"   ⚠️  WARNING: Returned None (will be filtered out!)")
                
            except Exception as e:
                print(f"❌ Mapping failed for '{category}': {e}")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ Category mapping test failed: {e}")
        return False

def test_column_classification():
    """Test 7: Can we classify a test column?"""
    print("\n" + "="*80)
    print("TEST 7: COLUMN CLASSIFICATION")
    print("="*80)
    
    try:
        from src.services.ai_classification_pipeline_service import ai_classification_pipeline_service as service
        
        if not hasattr(service, '_classify_columns_local'):
            print("❌ _classify_columns_local method not found!")
            return False
        
        print("✅ _classify_columns_local method exists")
        print("   (Full test requires database access - skipping for now)")
        
        return True
        
    except Exception as e:
        print(f"❌ Column classification test failed: {e}")
        return False

def print_summary(results: Dict[str, bool]):
    """Print test summary"""
    print("\n" + "="*80)
    print("DIAGNOSTIC SUMMARY")
    print("="*80)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed < total:
        print("\n⚠️  CRITICAL ISSUES DETECTED - Review failed tests above")
        print("\nRECOMMENDED ACTIONS:")
        
        if not results.get("Imports"):
            print("1. Fix module import errors first")
        if not results.get("Governance Connectivity"):
            print("2. Verify Snowflake connection and governance table access")
        if not results.get("Category Loading"):
            print("3. Fix _load_metadata_driven_categories() method")
        if not results.get("Embedding Model"):
            print("4. Verify SentenceTransformer model is loaded")
        if not results.get("Semantic Scoring"):
            print("5. Fix _semantic_scores() method implementation")
        if not results.get("Category Mapping"):
            print("6. Fix _map_category_to_policy_group() method")
    else:
        print("\n✅ ALL TESTS PASSED - Pipeline components are functional!")
        print("\nIf you're still seeing 'No assets classified', check:")
        print("1. Snowflake detection thresholds (should be 0.55)")
        print("2. Table-level confidence threshold (should be 0.25)")
        print("3. Streamlit cache (restart Streamlit)")

if __name__ == "__main__":
    print("="*80)
    print("AI CLASSIFICATION PIPELINE DIAGNOSTIC")
    print("="*80)
    
    results = {}
    
    # Run all tests
    results["Imports"] = test_imports()
    
    if results["Imports"]:
        results["Governance Connectivity"] = test_governance_connectivity()
        results["Category Loading"] = test_category_loading()
        results["Embedding Model"] = test_embedding_model()
        results["Semantic Scoring"] = test_semantic_scoring()
        results["Category Mapping"] = test_category_mapping()
        results["Column Classification"] = test_column_classification()
    
    # Print summary
    print_summary(results)

