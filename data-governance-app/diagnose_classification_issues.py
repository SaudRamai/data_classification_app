
import sys
import os
import logging
import numpy as np
from unittest.mock import MagicMock, patch

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("Diagnostic")

# Mock Streamlit
sys.modules["streamlit"] = MagicMock()
import streamlit as st
st.session_state = {}
st.secrets = {}

# Mock Snowflake Connector if needed (we'll try to let it run if it can, but likely need to mock for safety/environment)
# For this diagnostic, we want to inspect the CODE LOGIC more than the DB content if DB is inaccessible.
# However, to check centroid separation, we need centroids.
# Let's try to import the service.

try:
    from src.services.ai_classification_pipeline_service import AIClassificationPipelineService
    from src.services.ai_classification_service import ai_classification_service
except ImportError:
    # Adjust path if needed
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from src.services.ai_classification_pipeline_service import AIClassificationPipelineService
    from src.services.ai_classification_service import ai_classification_service

def diagnose():
    print("="*80)
    print("DIAGNOSTIC REPORT: AI CLASSIFICATION PIPELINE")
    print("="*80)

    service = AIClassificationPipelineService()
    
    # 1. Check Weight Auto-Tuning vs Usage
    print("\n[1] CHECKING WEIGHT APPLICATION")
    print("-" * 40)
    
    # Trigger auto-tuning
    service._embedder = MagicMock() # Mock embedder to simulate "healthy" state
    service._category_centroids = {'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6} # 6 centroids
    service._embed_ready = True
    
    service._auto_tune_parameters()
    print(f"Auto-tuned weights (Instance Variables): w_sem={service._w_sem}, w_kw={service._w_kw}")
    
    # Now check what _compute_governance_scores uses
    # It uses _category_scoring_weights
    service._category_scoring_weights = {'PII': {'w_sem': 0.6, 'w_kw': 0.25, 'w_pat': 0.15}}
    
    # Mock methods to capture used weights
    with patch.object(service, '_semantic_scores_governance_driven', return_value={'PII': 0.8}), \
         patch.object(service, '_keyword_scores', return_value={'PII': 0.5}), \
         patch.object(service, '_pattern_scores_governance_driven', return_value={'PII': 0.2}), \
         patch.object(service, '_context_quality_metrics', return_value={'len': 100}):
        
        scores = service._compute_governance_scores("test context")
        print(f"Scores computed: {scores}")
        
        # Verify if _w_sem was used? 
        # The code uses: weights = self._category_scoring_weights.get(category, {'w_sem': 0.6, ...})
        # It does NOT use self._w_sem
        
        if service._w_sem == 0.8 and service._category_scoring_weights['PII']['w_sem'] == 0.6:
            print("⚠️  MISMATCH DETECTED: Auto-tuned w_sem (0.8) is IGNORED in favor of metadata weights (0.6)")
        else:
            print("Weights match (unexpectedly)")

    # 2. Check Numeric PII Detection
    print("\n[2] CHECKING NUMERIC PII DETECTION LOGIC")
    print("-" * 40)
    
    # Test sample filtering logic
    # Code: if re.fullmatch(r"\s*\d+\s*", sv) and len(sv.strip()) < 5: continue
    import re
    samples = ["123", "1234", "12345", "123-45-6789", "555-1234"]
    filtered = []
    for sv in samples:
        if re.fullmatch(r"\s*\d+\s*", sv) and len(sv.strip()) < 5:
            continue
        filtered.append(sv)
    
    print(f"Input samples: {samples}")
    print(f"Filtered samples (passed to E5): {filtered}")
    
    if "123-45-6789" in filtered:
        print("⚠️  RISK: '123-45-6789' (SSN-like) is passed to E5.")
        print("   E5 embeddings for pure numeric patterns are often semantically meaningless or clustered poorly.")
    
    # 3. Check Centroid Separation (Simulation)
    print("\n[3] CHECKING CENTROID SEPARATION (SIMULATION)")
    print("-" * 40)
    
    # We can't easily check real centroids without DB, but we can check the code that calculates distance
    # The user provided a snippet. I'll verify if the service has a method for this or if we need to add one.
    # The service does NOT have a built-in diagnostic for this.
    
    print("Diagnostic suggestion: Run the following snippet in a connected environment:")
    print("""
    from scipy.spatial.distance import cosine
    for cat1 in service._category_centroids:
        for cat2 in service._category_centroids:
            if cat1 < cat2:
                dist = cosine(service._category_centroids[cat1], service._category_centroids[cat2])
                if dist < 0.2:
                    print(f"⚠️  WARNING: Centroids {cat1} and {cat2} are too close (dist={dist:.3f})")
    """)

    # 4. Check Fallback Mechanism
    print("\n[4] CHECKING FALLBACK MECHANISM")
    print("-" * 40)
    print(f"Fallback categories flag: {getattr(service, '_using_fallback_categories', 'Not Set')}")
    
    # 5. Check Thresholding Logic
    print("\n[5] CHECKING THRESHOLD LOGIC")
    print("-" * 40)
    # Code: threshold = self._category_thresholds.get(category, 0.30)
    # User says "15% Threshold is Arbitrary".
    # The code actually uses 0.30 (default) or metadata threshold.
    # But in _classify_columns_local (legacy?), it used 0.25.
    
    print(f"Default threshold in _compute_governance_scores: 0.30")
    print(f"Sensitive threshold in _classify_columns_local: 0.25")
    
    # 6. Check Governance Score Blending
    print("\n[6] CHECKING GOVERNANCE SCORE BLENDING")
    print("-" * 40)
    # User says: combined[cat] = 0.7 * base_val + 0.3 * gov_val
    # I didn't see this exact formula in the code I read.
    # I saw: score = (0.55 * s_val) + (0.25 * k_val) + (0.20 * r_val) in _classify_columns_local
    # And: dynamic weighting in _compute_governance_scores
    
    print("Code analysis shows:")
    print(" - _classify_columns_local uses FIXED weights: 0.55(Sem) + 0.25(Kw) + 0.20(Pat)")
    print(" - _compute_governance_scores uses METADATA weights (default 0.6/0.25/0.15)")
    print(" - No evidence of '0.7 * base + 0.3 * gov' blending in the inspected methods.")
    
if __name__ == "__main__":
    diagnose()
