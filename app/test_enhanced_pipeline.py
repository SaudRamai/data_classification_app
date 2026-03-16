
import logging
import math
import re
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
import sys
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

try:
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
except ImportError:
    logger.error("Required packages not installed. Please run: pip install sentence-transformers scikit-learn")
    sys.exit(1)

@dataclass
class ClassificationDecision:
    confidence_score: float
    classification: Optional[str]
    action: Optional[str]
    reasoning: List[str]
    review_required: bool

class EnhancedAIClassificationPipeline:
    def __init__(self):
        self._embed_backend = 'none'
        self._embedder = None
        self._category_centroids = {}
        self._category_tokens = {}
        self._category_patterns = {}
        
        # Initialize embeddings
        self._init_local_embeddings()
        
        # Initialize fallback categories for testing
        self._create_fallback_categories()
        
        # Decision thresholds
        self.HIGH_THRESHOLD = 0.88
        self.MEDIUM_THRESHOLD = 0.72

    def _init_local_embeddings(self):
        try:
            logger.info("Initializing SentenceTransformer embeddings...")
            # Using a better model as requested. 
            # Note: In a real deployment, we would use 'intfloat/e5-large-v2' or 'google/embedding-gemma-300m'
            # For this test environment, we'll try 'intfloat/e5-small-v2' to be safe with memory, 
            # but the logic supports any model.
            model_name = 'intfloat/e5-small-v2' 
            logger.info(f"Loading model: {model_name}")
            self._embedder = SentenceTransformer(model_name)
            self._embed_backend = 'sentence-transformers'
            logger.info("✓ Embeddings initialized successfully.")
        except Exception as e:
            logger.warning(f"Failed to load {model_name}, falling back to all-MiniLM-L6-v2: {e}")
            try:
                self._embedder = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
                self._embed_backend = 'sentence-transformers'
            except Exception as e2:
                logger.error(f"Failed to initialize fallback embeddings: {e2}")

    def _preprocess_text_local(self, text: str, remove_stopwords: bool = False) -> str:
        s = str(text or "")
        try:
            s = re.sub(r"[\n\r\t]+", " ", s)
            s = re.sub(r"\s+", " ", s).strip()
        except Exception:
            pass
        if not remove_stopwords:
            return s
        stops = {"the","a","an","and","or","of","to","on","at","by","with","from","as","is","are","was","were"}
        try:
            toks = [w for w in re.split(r"[^a-zA-Z0-9]+", s) if w and w.lower() not in stops]
            return " ".join(toks)
        except Exception:
            return s

    def _generate_category_examples(self, name: str, desc: str) -> List[str]:
        # ... (Same as before, simplified for brevity) ...
        n = (name or "").strip()
        d = (desc or "").strip()
        out = [n, d] if n and d else [n] if n else []
        # Add some simple variations
        out.append(f"{n} data")
        out.append(f"{n} information")
        return out

    def _create_fallback_categories(self):
        cats = [
            ("PII", "personally identifiable information customer email phone address ssn passport dob name identifier"),
            ("SOX", "sox financial reporting general ledger journal entry trial balance revenue expense accounting controls"),
            ("SOC2", "soc2 security availability confidentiality integrity privacy access log audit trail control policy"),
        ]
        centroids: Dict[str, Any] = {}
        
        logger.info("\n--- Generating Category Centroids ---")
        for name, desc in cats:
            ex = self._generate_category_examples(name, desc)
            # Important: e5 models need "query: " or "passage: " prefix. 
            # For centroids (which are like passages to be matched against), we might use "passage: "
            # But for symmetric comparison, maybe just the text. 
            # The e5 paper suggests "query: " for queries and "passage: " for documents.
            # Here we are comparing column metadata (query) to category descriptions (documents).
            
            # Let's prefix category examples with "passage: "
            ex_prefixed = [f"passage: {s}" for s in ex]
            
            vecs = self._embedder.encode(ex_prefixed, normalize_embeddings=True)
            mat = np.stack(vecs, axis=0)
            c = np.mean(mat, axis=0)
            n = float(np.linalg.norm(c) or 0.0)
            if n > 0:
                c = c / n
            centroids[name] = c
            logger.info(f"  Centroid generated for {name}")

        self._category_centroids = centroids

    def check_regex_patterns(self, text: str, category: str) -> float:
        # Mock regex check
        patterns = {
            "PII": [r"email", r"phone", r"ssn", r"address", r"name"],
            "SOX": [r"revenue", r"ledger", r"financial", r"account"],
            "SOC2": [r"key", r"token", r"password", r"secret"]
        }
        if category not in patterns:
            return 0.0
        
        for pat in patterns[category]:
            if re.search(pat, text, re.IGNORECASE):
                return 1.0
        return 0.0

    def analyze_table_context(self, text: str, category: str) -> float:
        # Mock context analysis
        # If "table" or "schema" context implies the category
        # For test, we'll assume the input text contains context
        if category.lower() in text.lower():
            return 0.8
        return 0.0

    def validate_metadata_alignment(self, text: str, category: str, context_map: Dict[str, Any] = None) -> float:
        # Mock metadata alignment
        meta_score = 0.5
        if context_map:
            dtype = str(context_map.get("data_type", "")).upper()
            if "DATE" in dtype or "TIME" in dtype:
                if any(x in category.upper() for x in ["EMAIL", "PHONE", "SSN", "NAME"]):
                    if not any(x in category.upper() for x in ["DOB", "BIRTH"]):
                            meta_score = 0.1
            elif "BOOLEAN" in dtype:
                meta_score = 0.0
            elif "NUMERIC" in dtype or "INT" in dtype or "FLOAT" in dtype:
                    if any(x in category.upper() for x in ["NAME", "EMAIL"]):
                        meta_score = 0.1
        return meta_score

    def analyze_data_distribution(self, text: str) -> float:
        # Mock distribution analysis
        return 0.5

    def calculate_enhanced_confidence(self, text: str, context_map: Dict[str, Any] = None) -> Dict[str, float]:
        """
        Multi-factor confidence scoring with weighted components
        """
        scores = {}
        
        # 1. Semantic Similarity Score
        # Prefix with "query: " for e5 model
        query_text = f"query: {text}"
        v_raw = self._embedder.encode([query_text], normalize_embeddings=True)
        v = np.asarray(v_raw[0], dtype=float)
        
        for cat, centroid in self._category_centroids.items():
            # Cosine similarity
            semantic_score = float(np.dot(v, centroid))
            semantic_score = max(0.0, semantic_score) # Clip at 0
            
            # 2. Pattern Match Score (regex-based)
            pattern_score = self.check_regex_patterns(text, cat)
            
            # 3. Context Validation Score
            context_score = self.analyze_table_context(text, cat)
            
            # 4. Metadata Consistency Score
            metadata_score = self.validate_metadata_alignment(text, cat, context_map)
            
            # 5. Statistical Distribution Score
            distribution_score = self.analyze_data_distribution(text)
            
            # Weighted Final Confidence
            # Weights: Semantic 35%, Pattern 25%, Context 20%, Metadata 15%, Distribution 5%
            final_confidence = (
                0.35 * semantic_score +
                0.25 * pattern_score +
                0.20 * context_score +
                0.15 * metadata_score +
                0.05 * distribution_score
            )
            
            scores[cat] = {
                "final": final_confidence,
                "components": {
                    "semantic": semantic_score,
                    "pattern": pattern_score,
                    "context": context_score,
                    "metadata": metadata_score,
                    "distribution": distribution_score
                }
            }
            
        return scores

    def make_decision(self, confidence_score: float, column_metadata: Dict[str, Any]) -> ClassificationDecision:
        reasoning = []
        classification = None
        action = None
        review_required = False
        
        if confidence_score >= self.HIGH_THRESHOLD:
            classification = "AUTO_CLASSIFY"
            action = "APPLY_TAG_AND_POLICY"
            reasoning.append(f"High confidence ({confidence_score:.2f}) exceeds threshold {self.HIGH_THRESHOLD}")
        
        elif confidence_score >= self.MEDIUM_THRESHOLD:
            classification = "MEDIUM_CONFIDENCE"
            action = "FLAG_FOR_HUMAN_REVIEW"
            review_required = True
            reasoning.append(f"Medium confidence ({confidence_score:.2f}) requires validation")
        
        else:
            classification = "EXCLUDE"
            action = "NO_ACTION"
            reasoning.append(f"Low confidence ({confidence_score:.2f}) below threshold")
        
        return ClassificationDecision(
            confidence_score=confidence_score,
            classification=classification,
            action=action,
            reasoning=reasoning,
            review_required=review_required
        )

    def test_classification(self, text: str, context_map: Dict[str, Any] = None):
        logger.info(f"\n=== Testing Enhanced Classification for Input: '{text}' ===")
        
        scores = self.calculate_enhanced_confidence(text, context_map)
        
        best_cat = None
        best_score = -1.0
        best_details = None
        
        for cat, data in scores.items():
            score = data['final']
            logger.info(f"Category: {cat} | Score: {score:.4f}")
            logger.info(f"  Components: {data['components']}")
            
            if score > best_score:
                best_score = score
                best_cat = cat
                best_details = data
        
        if best_cat:
            decision = self.make_decision(best_score, {})
            logger.info(f"🏆 Best Category: {best_cat}")
            logger.info(f"  Decision: {decision.classification}")
            logger.info(f"  Action: {decision.action}")
            logger.info(f"  Reasoning: {decision.reasoning}")
        else:
            logger.info("No classification found.")

if __name__ == "__main__":
    tester = EnhancedAIClassificationPipeline()
    
    # Test cases
    test_inputs = [
        ("customer_email | email address of the customer", {"data_type": "VARCHAR"}),
        ("revenue_2023 | total revenue for the fiscal year", {"data_type": "NUMBER"}),
        ("server_logs | access logs and security events", {"data_type": "VARIANT"}),
        ("random_column | some random data", {"data_type": "VARCHAR"})
    ]
    
    for inp, ctx in test_inputs:
        tester.test_classification(inp, ctx)
