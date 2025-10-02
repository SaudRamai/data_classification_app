"""
NLP Compliance Service

Provides NLP-based detection for unstructured or complex text fields.
- Lightweight regex/heuristics by default
- Optional spaCy NER if available (graceful fallback)
- Optional LLM hook (method stub) for advanced policies
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional
import re
import json

try:
    import spacy  # optional
except Exception:  # pragma: no cover
    spacy = None


class NLPComplianceService:
    def __init__(self):
        self._nlp = None
        if spacy is not None:
            try:
                # Try a small English model if present; otherwise keep None
                self._nlp = spacy.load('en_core_web_sm')
            except Exception:
                self._nlp = None

        # Simple regex patterns for PII-like content in free text
        self._patterns = {
            'EMAIL': re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I),
            'PHONE': re.compile(r"\+?[0-9\-()\s]{7,}", re.I),
            'SSN_US': re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b"),
            'CREDIT_CARD': re.compile(r"\b\d{13,19}\b"),
        }

    def analyze_text(self, text: str) -> Dict[str, Any]:
        """Analyze a single text blob for sensitive indicators.
        Returns detected entities, categories, and simple risk score.
        """
        if not text:
            return {'entities': [], 'categories': [], 'score': 0.0}

        entities: List[Dict[str, Any]] = []
        categories = set()

        # Regex pass
        for label, rx in self._patterns.items():
            for m in rx.finditer(text):
                entities.append({'label': label, 'text': m.group(0)})
                if label in ['EMAIL', 'PHONE', 'SSN_US', 'CREDIT_CARD']:
                    categories.add('PII')
                    if label in ['CREDIT_CARD']:
                        categories.add('Financial')

        # spaCy NER pass (if available)
        if self._nlp is not None:
            try:
                doc = self._nlp(text)
                for ent in doc.ents:
                    entities.append({'label': ent.label_, 'text': ent.text})
                    if ent.label_ in ['PERSON', 'GPE', 'ORG', 'NORP', 'DATE', 'CARDINAL']:
                        categories.add('PII')
            except Exception:
                pass

        # Score heuristic
        score = min(1.0, 0.2 * len(categories) + 0.05 * len(entities))
        return {'entities': entities, 'categories': sorted(categories), 'score': round(score, 2)}

    def batch_analyze(self, texts: List[str]) -> List[Dict[str, Any]]:
        return [self.analyze_text(t) for t in texts]

    def analyze_table_rows(self, rows: List[Dict[str, Any]], text_columns: Optional[List[str]] = None, max_rows: int = 100) -> Dict[str, Any]:
        """Analyze selected text columns across sample rows for sensitive content.
        rows: list of dicts (as returned by snowflake connector)
        """
        if not rows:
            return {'columns': {}, 'categories': [], 'score': 0.0}
        if text_columns is None and rows:
            # Choose likely text columns heuristically from first row
            sample = rows[0]
            text_columns = [k for k, v in sample.items() if isinstance(v, str)]
        columns: Dict[str, Any] = {}
        agg_categories = set()
        count = 0
        for r in rows:
            if count >= max_rows:
                break
            for c in text_columns:
                val = r.get(c)
                if not isinstance(val, str) or not val:
                    continue
                res = self.analyze_text(val)
                st = columns.setdefault(c, {'entities': [], 'categories': set(), 'score_sum': 0.0, 'n': 0})
                st['entities'].extend(res['entities'])
                st['categories'] |= set(res['categories'])
                st['score_sum'] += res['score']
                st['n'] += 1
                agg_categories |= set(res['categories'])
            count += 1
        # finalize
        for c, st in columns.items():
            st['categories'] = sorted(list(st['categories']))
            st['avg_score'] = round(st['score_sum'] / max(1, st['n']), 2)
            del st['score_sum']
            del st['n']
        return {'columns': columns, 'categories': sorted(list(agg_categories)), 'score': round(min(1.0, 0.1 * len(agg_categories)), 2)}

    def analyze_with_llm(self, prompts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Analyze one or more text prompts using Snowflake Cortex LLM.

        Input is flexible:
        - Each item may be {"text": "..."} or {"content": "..."} or a raw string.
        - If items contain role/content pairs, the 'content' is used.

        Returns a list of dicts with keys: entities, categories, score, raw.
        """
        # Lazy import to avoid circulars at module import time
        from src.connectors.snowflake_connector import snowflake_connector
        try:
            from src.config.settings import settings
            model_name = getattr(settings, 'CORTEX_MODEL', 'mistral-large')
        except Exception:
            model_name = 'mistral-large'

        results: List[Dict[str, Any]] = []

        def _extract_text(item: Any) -> str:
            try:
                if isinstance(item, dict):
                    if 'text' in item and isinstance(item['text'], str):
                        return item['text']
                    if 'content' in item and isinstance(item['content'], str):
                        return item['content']
                    # role/content message schema
                    if 'role' in item and 'content' in item:
                        return str(item.get('content') or '')
                if isinstance(item, str):
                    return item
                return str(item)
            except Exception:
                return str(item)

        def _build_prompt(text: str) -> str:
            instruction = (
                "You are a data compliance assistant. Extract sensitive entities and categories from the text. "
                "Return STRICT JSON with keys: entities (list of objects {label,text}), categories (list: PII, PHI, Financial, Auth, Other), "
                "score (0..1 risk). Do not include any explanation outside JSON."
            )
            examples = (
                "Example JSON: {\"entities\":[{\"label\":\"EMAIL\",\"text\":\"john@acme.com\"}],"
                "\"categories\":[\"PII\"],\"score\":0.6}"
            )
            return f"{instruction}\n{examples}\nText:\n{text}"

        for item in prompts:
            text = _extract_text(item)
            prompt = _build_prompt(text)
            try:
                rows = snowflake_connector.execute_query(
                    "SELECT SNOWFLAKE.CORTEX.COMPLETE(%(model)s, %(prompt)s) AS RESPONSE",
                    {"model": model_name, "prompt": prompt},
                )
                raw = rows[0]['RESPONSE'] if rows else ''
            except Exception as e:
                # Fallback to local heuristic if Cortex call fails
                local = self.analyze_text(text)
                local['raw'] = f"error: {e}"
                results.append(local)
                continue

            # Parse JSON from raw
            parsed: Dict[str, Any]
            try:
                parsed = json.loads(raw)
            except Exception:
                # Attempt to extract JSON substring
                try:
                    import re as _re
                    m = _re.search(r"\{[\s\S]*\}", raw)
                    parsed = json.loads(m.group(0)) if m else {}
                except Exception:
                    parsed = {}
            # Normalize output
            entities = parsed.get('entities') if isinstance(parsed, dict) else None
            categories = parsed.get('categories') if isinstance(parsed, dict) else None
            score = parsed.get('score') if isinstance(parsed, dict) else None
            if not isinstance(entities, list) or categories is None or score is None:
                # Soft fallback merge with heuristic
                heur = self.analyze_text(text)
                entities = heur.get('entities', []) if not isinstance(entities, list) else entities
                if not categories:
                    categories = heur.get('categories', [])
                try:
                    score = float(score) if score is not None else heur.get('score', 0.0)
                except Exception:
                    score = heur.get('score', 0.0)

            results.append({
                'entities': entities,
                'categories': categories,
                'score': round(float(score), 2) if isinstance(score, (int, float)) else 0.0,
                'raw': raw,
            })

        return results


nlp_compliance_service = NLPComplianceService()

# --- Module-level helpers used by pages/12_Policy.py ---
def parse_policy(text: str) -> Dict[str, Any]:
    """Lightweight parser that extracts draft requirements and controls from raw policy text.
    Heuristics:
    - Split into lines; treat lines starting with numbers or dashes as requirement/control candidates
    - Run entity/category analysis to tag categories (PII, Financial, etc.)
    Returns: {requirements: [...], controls: [...], notes: [...]} structure.
    """
    try:
        lines = [l.strip() for l in (text or '').splitlines()]
        reqs: List[str] = []
        ctrls: List[str] = []
        notes: List[str] = []
        for ln in lines:
            if not ln:
                continue
            lower = ln.lower()
            if lower.startswith(tuple(["1.", "2.", "3.", "4.", "5."])) or lower.startswith(("- ", "• ", "* ")):
                # classify into requirement vs control by keyword hints
                if any(k in lower for k in ["must", "shall", "required", "ensure", "enforce"]):
                    reqs.append(ln)
                elif any(k in lower for k in ["control", "check", "test", "evidence", "masking", "row access"]):
                    ctrls.append(ln)
                else:
                    # default to requirement
                    reqs.append(ln)
            else:
                notes.append(ln)
        # Run a coarse NLP pass on the whole text to tag categories
        analysis = nlp_compliance_service.analyze_text(text or '')
        return {
            "requirements": reqs[:200],
            "controls": ctrls[:200],
            "notes": notes[:200],
            "categories": analysis.get("categories", []),
            "score": analysis.get("score", 0.0),
        }
    except Exception as e:
        return {"requirements": [], "controls": [], "notes": [f"parse_error: {e}"]}


def generate_controls_and_checks(text: str, framework: str) -> Dict[str, Any]:
    """Produce draft framework requirements, controls, and automated check suggestions.
    Uses simple heuristics and categories from the NLP analysis to recommend checks such as:
    - Tag coverage check for datasets matching keywords
    - CIA minimums enforcement for sensitive categories
    - Masking/row access policy presence
    """
    try:
        parsed = parse_policy(text or '')
        cats = set(parsed.get("categories") or [])
        fw = (framework or "Framework").upper()
        requirements = [
            {"framework": fw, "id": f"REQ-{i+1:03d}", "text": r}
            for i, r in enumerate(parsed.get("requirements") or [])
        ][:50]
        controls = [
            {"framework": fw, "id": f"CTRL-{i+1:03d}", "text": c}
            for i, c in enumerate(parsed.get("controls") or [])
        ][:50]
        # Suggested automated checks
        checks: List[Dict[str, Any]] = []
        if "PII" in cats:
            checks.append({
                "code": "PII_MINIMUMS",
                "description": "PII datasets must be at least Restricted (C2) and have masking policy",
                "rule": "C >= 2 AND HAS_MASKING_POLICY = TRUE",
            })
        if "Financial" in cats or "FINANCIAL" in (text or '').upper():
            checks.append({
                "code": "SOX_MINIMUMS",
                "description": "Financial/SOX datasets must be Restricted (C2) or Confidential (C3) and have row access/masking controls",
                "rule": "(C >= 2) AND (HAS_MASKING_POLICY = TRUE OR HAS_ROW_ACCESS_POLICY = TRUE)",
            })
        checks.append({
            "code": "TAG_COVERAGE",
            "description": "All inventoried assets must have standardized classification and CIA tags",
            "rule": "HAS_TAGS(DATA_CLASSIFICATION, CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL)",
        })
        return {"framework": fw, "requirements": requirements, "controls": controls, "checks": checks}
    except Exception as e:
        return {"framework": framework, "requirements": [], "controls": [], "checks": [], "error": str(e)}
