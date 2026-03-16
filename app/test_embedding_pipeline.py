
import logging
import math
import re
import numpy as np
from typing import List, Dict, Any, Optional
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    logger.error("sentence-transformers not installed. Please run: pip install sentence-transformers")
    sys.exit(1)

class TestAIClassificationPipeline:
    def __init__(self):
        self._embed_backend = 'none'
        self._embedder = None
        self._category_centroids = {}
        self._category_tokens = {}
        self._category_patterns = {}
        self._embed_cache = {}
        
        # Tuning defaults
        self._w_sem = 0.7
        self._w_kw = 0.3
        self._w_pt = 0.2
        
        # Initialize embeddings
        self._init_local_embeddings()
        
        # Initialize fallback categories for testing
        self._create_fallback_categories()

    def _init_local_embeddings(self):
        try:
            logger.info("Initializing SentenceTransformer embeddings...")
            self._embedder = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
            self._embed_backend = 'sentence-transformers'
            logger.info("✓ Embeddings initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize embeddings: {e}")

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
        n = (name or "").strip()
        d = (desc or "").strip()
        out: List[str] = []
        
        if n: out.append(n)
        if d: out.append(d)

        raw_tokens: List[str] = []
        for s in [n, d]:
            for w in re.split(r"[^a-zA-Z0-9]+", s):
                w2 = w.strip()
                if len(w2) >= 3:
                    raw_tokens.append(w2)

        stops = {"the","a","an","and","or","of","to","in","for","on","at","by","with","from","as","is","are","was","were"}
        toks: List[str] = []
        seen: set = set()
        for t in raw_tokens:
            tl = t.lower()
            if tl in stops: continue
            if tl not in seen:
                toks.append(t)
                seen.add(tl)

        phrases: List[str] = []
        for t in toks[:12]:
            phrases.append(t)
            phrases.append(f"contains {t}")
            phrases.append(f"{t} field")
            phrases.append(f"{t} column")
        
        domain_patterns: List[str] = []
        for t in toks[:8]:
            domain_patterns.append(f"{t} record")
            domain_patterns.append(f"{t} value")
            domain_patterns.append(f"{t} attribute")
        
        ex = out + phrases + domain_patterns
        
        seen2 = set()
        dedup: List[str] = []
        for s in ex:
            sl = s.lower().strip()
            if sl and sl not in seen2:
                dedup.append(s.strip())
                seen2.add(sl)
        
        return dedup[:64]

    def _generate_category_tokens(self, name: str, desc: str) -> List[str]:
        n = (name or "").strip()
        d = (desc or "").strip()
        raw: List[str] = []
        for s in [n, d]:
            for w in re.split(r"[^a-zA-Z0-9]+", s):
                w2 = w.strip()
                if len(w2) >= 3:
                    raw.append(w2)
        stops = {"the","a","an","and","or","of","to","in","for","on","at","by","with","from","as","is","are","was","were","data","info","information"}
        out: List[str] = []
        seen = set()
        for t in raw:
            tt = re.sub(r"[_\-]+", " ", str(t)).strip()
            tl = tt.lower()
            if not tt or tl in stops: continue
            if tl not in seen:
                out.append(tt)
                seen.add(tl)
        return out[:64]

    def _create_fallback_categories(self):
        cats = [
            ("PII", "personally identifiable information customer email phone address ssn passport dob name identifier"),
            ("SOX", "sox financial reporting general ledger journal entry trial balance revenue expense accounting controls"),
            ("SOC2", "soc2 security availability confidentiality integrity privacy access log audit trail control policy"),
        ]
        centroids: Dict[str, Any] = {}
        tokens_out: Dict[str, List[str]] = {}
        
        logger.info("\n--- Generating Category Centroids ---")
        for name, desc in cats:
            logger.info(f"Processing category: {name}")
            
            # Tokens
            toks = self._generate_category_tokens(name, desc)
            tokens_out[name] = toks
            logger.info(f"  Tokens: {toks}")
            
            # Embeddings
            ex = self._generate_category_examples(name, desc)
            logger.info(f"  Examples ({len(ex)}): {ex[:5]} ...")
            
            ex2 = [self._preprocess_text_local(s, remove_stopwords=True) for s in ex]
            vecs = self._embedder.encode(ex2, normalize_embeddings=True)
            mat = np.stack(vecs, axis=0)
            c = np.mean(mat, axis=0)
            n = float(np.linalg.norm(c) or 0.0)
            if n > 0:
                c = c / n
            centroids[name] = c
            logger.info(f"  Centroid generated (norm={n:.4f})")

        self._category_centroids = centroids
        self._category_tokens = tokens_out

    def _semantic_scores(self, text: str) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        if not text: return scores
        
        t = str(text or "")
        v_raw = self._embedder.encode([t], normalize_embeddings=True)
        v = np.asarray(v_raw[0], dtype=float)
        n = float(np.linalg.norm(v) or 0.0)
        if n > 0: v = v / n
        
        logger.info(f"\nInput Embedding Norm: {n:.4f}")

        raw: Dict[str, float] = {}
        for cat, c in self._category_centroids.items():
            if c is None: continue
            sim = float(np.dot(v, c))
            conf = max(0.0, min(1.0, (sim + 1.0) / 2.0))
            raw[cat] = conf
            logger.info(f"  Similarity to {cat}: {sim:.4f} (normalized: {conf:.4f})")

        if not raw: return {}

        # Refined scoring logic: Use absolute similarity thresholds to avoid boosting noise.
        threshold = 0.575 
        
        for k, conf in raw.items():
            if conf < threshold:
                score = 0.0
            else:
                # Normalize the range [threshold, 1.0] to [0.0, 1.0]
                score = (conf - threshold) / (1.0 - threshold)
                score = pow(score, 1.2)
            
            scores[k] = max(0.0, min(1.0, score))
            
        return scores

    def _keyword_scores(self, text: str) -> Dict[str, float]:
        t = (text or '').lower()
        out: Dict[str, float] = {}
        for cat, toks in self._category_tokens.items():
            hits = 0
            for tok in toks:
                if tok.lower() in t:
                    hits += 1
            out[cat] = max(0.0, min(1.0, math.log1p(hits) / math.log1p(10)))
        return out

    def test_classification(self, text: str):
        logger.info(f"\n=== Testing Classification for Input: '{text}' ===")
        
        ptxt = self._preprocess_text_local(text)
        logger.info(f"Preprocessed text: '{ptxt}'")
        
        sem = self._semantic_scores(ptxt)
        logger.info(f"Semantic Scores (boosted): {sem}")
        
        kw = self._keyword_scores(ptxt)
        logger.info(f"Keyword Scores: {kw}")
        
        combined = {}
        cats = set(list(sem.keys()) + list(kw.keys()))
        
        for cat in cats:
            s = float(sem.get(cat, 0.0))
            k = float(kw.get(cat, 0.0))
            v = (self._w_sem * s) + (self._w_kw * k)
            combined[cat] = max(0.0, min(1.0, v))
            
        logger.info(f"Combined Scores (w_sem={self._w_sem}, w_kw={self._w_kw}): {combined}")
        
        if combined:
            best_cat = max(combined, key=combined.get)
            logger.info(f"🏆 Best Category: {best_cat} (Score: {combined[best_cat]:.4f})")
        else:
            logger.info("No classification found.")

if __name__ == "__main__":
    tester = TestAIClassificationPipeline()
    
    # Test cases
    test_inputs = [
        "customer_email | email address of the customer",
        "revenue_2023 | total revenue for the fiscal year",
        "server_logs | access logs and security events",
        "random_column | some random data"
    ]
    
    for inp in test_inputs:
        tester.test_classification(inp)
