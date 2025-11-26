"""
AI Classification Pipeline - Diagnostic Script

Run this to diagnose why "No assets were successfully classified"
"""

import logging

# Setup logging to see debug messages
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def diagnose_classification_pipeline():
    """Run comprehensive diagnostics on the classification pipeline"""
    
    print("=" * 80)
    print("AI CLASSIFICATION PIPELINE DIAGNOSTICS")
    print("=" * 80)
    print()
    
    # Import service
    try:
        from src.services.ai_classification_pipeline_service import AIClassificationPipelineService
        service = AIClassificationPipelineService()
        print("✓ Service imported successfully")
    except Exception as e:
        print(f"✗ Failed to import service: {e}")
        return
    
    print()
    print("-" * 80)
    print("STEP 1: Check Governance Metadata Loading")
    print("-" * 80)
    
    # Initialize embeddings and load governance metadata
    try:
        service._init_local_embeddings()
        print("✓ Embeddings initialized")
    except Exception as e:
        print(f"✗ Failed to initialize embeddings: {e}")
        import traceback
        traceback.print_exc()
    
    # Check what was loaded
    print()
    print("Governance Metadata Status:")
    print(f"  - Embed Backend: {getattr(service, '_embed_backend', 'NOT SET')}")
    print(f"  - Embed Ready: {getattr(service, '_embed_ready', False)}")
    
    centroids = getattr(service, '_category_centroids', {})
    print(f"  - Category Centroids: {len(centroids)}")
    if centroids:
        valid_centroids = len([c for c in centroids.values() if c is not None])
        print(f"    • Valid centroids: {valid_centroids}")
        print(f"    • Categories: {list(centroids.keys())}")
    else:
        print("    ⚠️ NO CENTROIDS LOADED!")
    
    keywords = getattr(service, '_category_keywords', {})
    print(f"  - Category Keywords: {sum(len(kws) for kws in keywords.values())} total")
    if keywords:
        for cat, kws in keywords.items():
            print(f"    • {cat}: {len(kws)} keywords")
    else:
        print("    ⚠️ NO KEYWORDS LOADED!")
    
    patterns = getattr(service, '_category_patterns', {})
    print(f"  - Category Patterns: {sum(len(pats) for pats in patterns.values())} total")
    if patterns:
        for cat, pats in patterns.items():
            print(f"    • {cat}: {len(pats)} patterns")
    else:
        print("    ⚠️ NO PATTERNS LOADED!")
    
    thresholds = getattr(service, '_category_thresholds', {})
    print(f"  - Category Thresholds:")
    if thresholds:
        for cat, thr in thresholds.items():
            print(f"    • {cat}: {thr:.2f}")
    else:
        print("    ⚠️ NO THRESHOLDS LOADED!")
    
    policy_map = getattr(service, '_policy_group_by_category', {})
    print(f"  - Policy Group Mapping: {len(policy_map)} categories mapped")
    if policy_map:
        for cat, policy in policy_map.items():
            print(f"    • {cat} → {policy}")
    else:
        print("    ⚠️ NO POLICY MAPPING! Categories won't map to PII/SOX/SOC2")
    
    print()
    print("-" * 80)
    print("STEP 2: Test Classification on Sample Text")
    print("-" * 80)
    
    # Test semantic scoring
    test_cases = [
        ("customer_email", "Email column containing customer contact information"),
        ("ssn", "Social Security Number for employees"),
        ("credit_card_number", "Credit card numbers for payments"),
        ("account_balance", "Financial account balance"),
        ("login_password", "User login password hash"),
    ]
    
    print()
    print("Testing governance-driven scoring:")
    for col_name, description in test_cases:
        context = f"Column: {col_name} | {description}"
        print(f"\n  Test: {context}")
        
        # Test semantic scores
        try:
            if hasattr(service, '_semantic_scores_governance_driven'):
                sem_scores = service._semantic_scores_governance_driven(context)
                print(f"    Semantic scores: {sem_scores}")
        except Exception as e:
            print(f"    ✗ Semantic scoring failed: {e}")
        
        # Test keyword scores
        try:
            if hasattr(service, '_keyword_scores'):
                kw_scores = service._keyword_scores(context)
                print(f"    Keyword scores: {kw_scores}")
        except Exception as e:
            print(f"    ✗ Keyword scoring failed: {e}")
        
        # Test pattern scores
        try:
            if hasattr(service, '_pattern_scores_governance_driven'):
                pat_scores = service._pattern_scores_governance_driven(context)
                print(f"    Pattern scores: {pat_scores}")
        except Exception as e:
            print(f"    ✗ Pattern scoring failed: {e}")
        
        # Test combined scores
        try:
            if hasattr(service, '_compute_governance_scores'):
                combined = service._compute_governance_scores(context)
                print(f"    ✓ Combined scores: {combined}")
                
                if combined:
                    best_cat, best_score = max(combined.items(), key=lambda x: x[1])
                    
                    # Test mapping
                    if hasattr(service, '_map_category_to_policy_group'):
                        mapped = service._map_category_to_policy_group(best_cat)
                        print(f"    ✓ Best: {best_cat} ({best_score:.2f}) → {mapped}")
                        
                        # Check if it would pass filtering
                        if mapped in {'PII', 'SOX', 'SOC2'} and best_score >= 0.25:
                            print(f"    ✓ WOULD PASS FILTER")
                        else:
                            print(f"    ✗ WOULD BE FILTERED OUT (mapped={mapped}, score={best_score:.2f})")
                else:
                    print(f"    ⚠️ NO SCORES - would be filtered out")
        except Exception as e:
            print(f"    ✗ Combined scoring failed: {e}")
            import traceback
            traceback.print_exc()
    
    print()
    print("-" * 80)
    print("STEP 3: Check Actual Database Assets")
    print("-" * 80)
    
    # Try to discover assets
    try:
        db = service._get_active_database()
        print(f"\n  Active Database: {db}")
        
        if db and db.upper() not in ('NONE', '(NONE)', 'NULL', 'UNKNOWN', ''):
            assets = service._discover_assets(db)
            print(f"  Discovered Assets: {len(assets)}")
            
            if assets:
                print(f"\n  Sample assets (first 5):")
                for asset in assets[:5]:
                    print(f"    • {asset.get('schema')}.{asset.get('table')}")
                
                # Try classifying first asset
                print(f"\n  Testing classification on first asset...")
                test_asset = assets[0]
                print(f"    Asset: {test_asset.get('schema')}.{test_asset.get('table')}")
                
                try:
                    result = service._classify_table_governance_driven(db, test_asset)
                    print(f"\n    Classification Result:")
                    print(f"      Category: {result.get('category')}")
                    print(f"      Confidence: {result.get('confidence', 0.0):.2f}")
                    print(f"      Status: {result.get('status')}")
                    if 'error' in result:
                        print(f"      Error: {result.get('error')}")
                    
                    # Check if it would pass filter
                    cat = result.get('category')
                    conf = result.get('confidence', 0.0)
                    
                    print(f"\n    Filter Check:")
                    print(f"      Category in {{'PII', 'SOX', 'SOC2'}}: {cat in {'PII', 'SOX', 'SOC2'}}")
                    print(f"      Confidence >= 0.25: {conf >= 0.25}")
                    
                    if cat in {'PII', 'SOX', 'SOC2'} and conf >= 0.25:
                        print(f"      ✓ WOULD PASS FILTER")
                    else:
                        print(f"      ✗ WOULD BE FILTERED OUT")
                        print(f"         Reason: ", end="")
                        if cat not in {'PII', 'SOX', 'SOC2'}:
                            print(f"Category '{cat}' not in PII/SOX/SOC2")
                        if conf < 0.25:
                            print(f"Confidence {conf:.2f} < 0.25")
                    
                except Exception as e:
                    print(f"    ✗ Classification failed: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"  ⚠️ No assets discovered!")
        else:
            print(f"  ⚠️ Invalid database: {db}")
    except Exception as e:
        print(f"  ✗ Asset discovery failed: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print("=" * 80)
    print("DIAGNOSIS COMPLETE")
    print("=" * 80)
    print()
    print("NEXT STEPS:")
    print("1. Review the output above to identify which step is failing")
    print("2. Check Snowflake governance tables if metadata is not loaded")
    print("3. Verify detection thresholds are not too high (should be 0.45-0.55)")
    print("4. Ensure policy mapping is working (categories → PII/SOX/SOC2)")
    print()

if __name__ == "__main__":
    diagnose_classification_pipeline()
