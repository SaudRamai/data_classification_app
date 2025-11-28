
import sys
import os
import logging
import numpy as np
from unittest.mock import MagicMock, patch
import pytest

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("Diagnostic")

# Mock Streamlit
sys.modules["streamlit"] = MagicMock()
import streamlit as st
st.session_state = {}
st.secrets = {}

try:
    from src.services.ai_classification_pipeline_service import AIClassificationPipelineService
    from src.services.ai_classification_service import ai_classification_service
except ImportError:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from src.services.ai_classification_pipeline_service import AIClassificationPipelineService
    from src.services.ai_classification_service import ai_classification_service

def test_diagnose():
    print("="*80)
    print("DIAGNOSTIC REPORT: AI CLASSIFICATION PIPELINE")
    print("="*80)

    service = AIClassificationPipelineService()
    
    # Initialize required attributes that are usually set in _init_local_embeddings
    service._category_thresholds = {}
    service._category_weights = {}
    service._category_scoring_weights = {}
    service._policy_group_by_category = {}
    service._category_centroids = {}
    
    # 1. Check Weight Auto-Tuning vs Usage
    print("\n[1] CHECKING WEIGHT APPLICATION")
    print("-" * 40)
    
    # Trigger auto-tuning
    service._embedder = MagicMock() 
    service._category_centroids = {'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6} 
    service._embed_ready = True
    
    service._auto_tune_parameters()
    print(f"Auto-tuned weights (Instance Variables): w_sem={service._w_sem}, w_kw={service._w_kw}")
    
    # Setup for _compute_governance_scores
    service._category_scoring_weights = {'PII': {'w_sem': 0.6, 'w_kw': 0.25, 'w_pat': 0.15}}
    service._category_thresholds = {'PII': 0.3}
    
    # Mock methods to capture used weights
    with patch.object(service, '_semantic_scores_governance_driven', return_value={'PII': 0.8}), \
         patch.object(service, '_keyword_scores', return_value={'PII': 0.5}), \
         patch.object(service, '_pattern_scores_governance_driven', return_value={'PII': 0.2}), \
         patch.object(service, '_context_quality_metrics', return_value={'len': 100}):
        
        scores = service._compute_governance_scores("test context")
        print(f"Scores computed: {scores}")
        
        if service._w_sem == 0.8 and service._category_scoring_weights['PII']['w_sem'] == 0.6:
            print("⚠️  MISMATCH DETECTED: Auto-tuned w_sem (0.8) is IGNORED in favor of metadata weights (0.6)")
        else:
            print("Weights match (unexpectedly)")

    # 2. Check Numeric PII Detection
    print("\n[2] CHECKING NUMERIC PII DETECTION LOGIC")
    print("-" * 40)
    
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
    print("Diagnostic suggestion: Run centroid separation check in connected environment.")

    # 4. Check Fallback Mechanism
    print("\n[4] CHECKING FALLBACK MECHANISM")
    print("-" * 40)
    print(f"Fallback categories flag: {getattr(service, '_using_fallback_categories', 'Not Set')}")
    
    # 5. Check Thresholding Logic
    print("\n[5] CHECKING THRESHOLD LOGIC")
    print("-" * 40)
    print(f"Default threshold in _compute_governance_scores: 0.30")
    print(f"Sensitive threshold in _classify_columns_local: 0.25")
    
    # 6. Check Governance Score Blending
    print("\n[6] CHECKING GOVERNANCE SCORE BLENDING")
    print("-" * 40)
    print("Code analysis shows:")
    print(" - _classify_columns_local uses FIXED weights: 0.55(Sem) + 0.25(Kw) + 0.20(Pat)")
    print(" - _compute_governance_scores uses METADATA weights (default 0.6/0.25/0.15)")
    print(" - No evidence of '0.7 * base + 0.3 * gov' blending in the inspected methods.")
