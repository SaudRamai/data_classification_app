from __future__ import annotations

from typing import List, Dict, Any, Optional, Tuple, Iterable
import re
import math
import pandas as pd

from src.services.ai_classification_service import AIClassificationService


class InternalSensitiveEngine:
    """
    Internal sensitive data detection engine (no external AI calls).

    - Table-level detection with semantic name cues, sampled regex scans, and a lightweight internal model
    - Column-level drilldown with weighted confidence and CIA/policy mapping
    - Works with Snowflake (if configured), virtual tables, and CSV uploads via AIClassificationService adapters
    """

    # Global ignore lists (db/schema) can be provided at runtime
    def __init__(self, ai: Optional[AIClassificationService] = None) -> None:
        self.ai = ai or AIClassificationService()
        self._patterns = self._build_patterns()

    # ---------------- Core APIs ----------------
    def register_csv(self, table_name: str, df: pd.DataFrame) -> None:
        cols = [{"name": c, "type": None} for c in df.columns]
        self.ai.set_virtual_table_profile(table_name, columns=cols, samples=df)

    def analyze_tables(
        self,
        table_names: List[str],
        global_ignore: Optional[Dict[str, Iterable[str]]] = None,
        sample_rows: int = 300,
    ) -> List[Dict[str, Any]]:
        """
        Return table-level results in the required format:
        [{"table_name": str, "sensitivity_score": 0-100, "sensitive": bool, "predominant_type": str}]
        """
        ignore_db = set([x.upper() for x in (global_ignore or {}).get("databases", [])])
        ignore_schema = set([x.upper() for x in (global_ignore or {}).get("schemas", [])])

        out: List[Dict[str, Any]] = []
        for fqn in table_names:
            try:
                db, schema, table = self._split_fqn_flexible(fqn)
                if db.upper() in ignore_db or schema.upper() in ignore_schema:
                    continue
                score, predominant = self._table_sensitivity_score(fqn, sample_rows)
                out.append({
                    "table_name": fqn,
                    "sensitivity_score": int(round(score)),
                    "sensitive": score >= 50,
                    "predominant_type": predominant or "Internal"
                })
            except Exception:
                out.append({
                    "table_name": fqn,
                    "sensitivity_score": 0,
                    "sensitive": False,
                    "predominant_type": "Internal"
                })
        return out

    def analyze_columns(
        self,
        table_name: str,
        sample_rows: int = 300,
    ) -> List[Dict[str, Any]]:
        """
        Return column-level results per sensitive table in the required format.
        """
        cols_meta = self.ai.get_column_metadata(table_name)
        df = self.ai.get_sample_data(table_name, sample_rows)
        df = df if isinstance(df, pd.DataFrame) else pd.DataFrame(df)

        results: List[Dict[str, Any]] = []
        for col in cols_meta or []:
            cname = str(col.get("COLUMN_NAME") or "")
            ctype = str(col.get("DATA_TYPE") or "STRING")
            name_score, name_types = self._name_type_score(cname)

            values = []
            if not df.empty and cname in df.columns:
                values = [self._as_text(v) for v in df[cname].head(sample_rows).tolist()]

            pat_score, pat_freqs, pat_types = self._pattern_frequency(values)
            stats_score = self._stats_score(values)

            # Weighted confidence: name 0.35, pattern strength 0.55, stats 0.10
            confidence = int(round(100.0 * min(1.0, 0.35 * name_score + 0.55 * pat_score + 0.10 * stats_score)))

            # Determine sensitive type priority mapping into required coarse set
            coarse_type = self._coarse_type(self._pick_predominant(list(set(name_types + pat_types))))

            C, I, A = self._cia_from_type(coarse_type)
            policy = self._policy_from_cia_and_type(C, I, A, coarse_type)

            reasoning = self._reasoning_for_column(cname, name_types, pat_freqs, stats_score, coarse_type)

            results.append({
                "column_name": cname,
                "data_type": ctype,
                "sensitive_type": coarse_type,
                "confidence_score": confidence,
                "CIA": {"C": C, "I": I, "A": A},
                "policy_label": policy,
                "reasoning": reasoning,
                "auto_classified": confidence >= 85,
            })
        return results

    # ---------------- Scoring helpers ----------------
    def _table_sensitivity_score(self, table_name: str, sample_rows: int) -> Tuple[float, Optional[str]]:
        # Column/Name cues
        cols = self.ai.get_column_metadata(table_name) or []
        df = self.ai.get_sample_data(table_name, min(max(100, sample_rows), 1000))
        df = df if isinstance(df, pd.DataFrame) else pd.DataFrame(df)

        name_hits = 0
        name_types: List[str] = []
        for c in cols:
            sc, tys = self._name_type_score(str(c.get("COLUMN_NAME") or ""))
            name_hits += 1 if sc > 0 else 0
            name_types.extend(tys)

        # Pattern frequency across table
        pat_score_acc = 0.0
        pat_types_acc: List[str] = []
        if not df.empty:
            # scan up to 20 columns to limit cost
            for cname in df.columns[: min(20, len(df.columns))]:
                s = [self._as_text(v) for v in df[cname].head(min(1000, sample_rows)).tolist()]
                ps, _, pt = self._pattern_frequency(s)
                pat_score_acc += ps
                pat_types_acc.extend(pt)
            if len(df.columns) > 0:
                pat_score_acc /= float(min(20, len(df.columns)))

        # Features
        sensitive_cols_est = name_hits
        pattern_intensity = pat_score_acc  # 0..1
        semantic_hint = 1.0 if any(t in name_types for t in ["PII", "Financial", "Regulatory"]) else 0.0

        # Lightweight internal classifier (logistic-ish heuristic)
        score = (
            35.0 * min(1.0, sensitive_cols_est / max(1.0, len(cols) or 1)) +
            50.0 * pattern_intensity +
            15.0 * semantic_hint
        )
        predominant = self._coarse_type(self._pick_predominant(list(set(name_types + pat_types_acc))))
        return max(0.0, min(100.0, score)), predominant

    def _name_type_score(self, name: str) -> Tuple[float, List[str]]:
        up = (name or "").upper()
        types: List[str] = []
        hits = 0
        for t, spec in self._patterns.items():
            tokens = spec.get("name_tokens", [])
            if any(tok in up for tok in tokens):
                types.append(t)
                hits += 1
        score = 1.0 if hits > 0 else 0.0
        return score, list(sorted(set(types)))

    def _pattern_frequency(self, values: List[str]) -> Tuple[float, Dict[str, float], List[str]]:
        """Return (score 0..1, per-type strength, detected types).

        Strength per type uses:
        strength = match_ratio * (0.7 + 0.3 * consistency)
        and is then weighted by category importance.
        """
        if not values:
            return 0.0, {}, []
        cat_weights: Dict[str, float] = {
            "PII": 1.0,
            "PHI": 0.9,
            "Financial": 0.9,
            "PCI": 1.0,
            "SOX": 0.6,
            "Regulatory": 0.6,
            "Operational": 0.4,
            "TradeSecret": 0.7,
            "SOC": 0.5,
        }
        counted_types = 0
        strengths: Dict[str, float] = {}
        detected: List[str] = []
        for t, spec in self._patterns.items():
            rx_list = spec.get("value_regex", [])
            if not rx_list:
                continue
            considered = 0
            matched = 0
            rx_match_counts: Dict[int, int] = {}
            for v in values:
                v = (v or "").strip()
                if not v:
                    continue
                considered += 1
                hit_idx = None
                for idx, rx in enumerate(rx_list):
                    try:
                        if re.search(rx, v):
                            hit_idx = idx
                            break
                    except Exception:
                        continue
                if hit_idx is not None:
                    matched += 1
                    rx_match_counts[hit_idx] = rx_match_counts.get(hit_idx, 0) + 1
            if considered == 0:
                continue
            match_ratio = float(matched) / float(considered)
            most_common = max(rx_match_counts.values()) if rx_match_counts else 0
            consistency = (float(most_common) / float(matched)) if matched else 0.0
            raw_strength = match_ratio * (0.7 + 0.3 * consistency)
            weighted = raw_strength * float(cat_weights.get(t, 0.5))
            strengths[t] = round(weighted, 3)
            if weighted >= 0.08:
                detected.append(t)
            counted_types += 1
        if counted_types == 0:
            return 0.0, strengths, detected
        score = sum(strengths.values()) / float(max(1, counted_types))
        return min(1.0, score), strengths, detected

    def _stats_score(self, values: List[str]) -> float:
        if not values:
            return 0.0
        vals = [v for v in values if v is not None and v != ""]
        if not vals:
            return 0.0
        uniq_ratio = len(set(vals)) / float(len(vals))
        lens = [len(v) for v in vals]
        avg_len = (sum(lens) / float(len(lens))) if lens else 0.0
        # entropy of first N values to limit cost
        ent = [self._entropy(v) for v in vals[:200]]
        avg_entropy = (sum(ent) / float(len(ent))) if ent else 0.0
        # Heuristic: identifiers typically high uniqueness and moderate entropy/length
        if uniq_ratio >= 0.6 and avg_len >= 5:
            return 1.0
        if uniq_ratio >= 0.4 and avg_len >= 4 and avg_entropy >= 2.0:
            return 0.7
        if uniq_ratio >= 0.25 and avg_len >= 4:
            return 0.5
        return 0.0

    # ---------------- Mapping helpers ----------------
    def _coarse_type(self, t: Optional[str]) -> str:
        if not t:
            return "Internal"
        u = str(t).upper()
        if u in ("PII", "EMAIL", "PHONE", "SSN"):
            return "PII"
        if u in ("PHI",):
            return "Regulatory"
        if u in ("FINANCIAL", "PCI"):
            return "Financial"
        if u in ("SOX", "SOC"):
            return "Regulatory"
        return "Internal"

    def _pick_predominant(self, types: List[str]) -> Optional[str]:
        if not types:
            return None
        order = {"PCI": 0, "PHI": 1, "PII": 2, "FINANCIAL": 3, "SOX": 4, "SOC": 5}
        return sorted(types, key=lambda x: order.get(str(x), 99))[0]

    def _cia_from_type(self, coarse: str) -> Tuple[int, int, int]:
        c = i = a = 0
        u = coarse.upper()
        if u in ("PII", "FINANCIAL", "REGULATORY"):
            c = max(c, 2)
        if u in ("REGULATORY",):
            c = max(c, 3)
        if u in ("FINANCIAL",):
            i = max(i, 2)
        return c, i, a

    def _policy_from_cia_and_type(self, c: int, i: int, a: int, coarse: str) -> str:
        # Simple mapping: C3->Restricted, C2->Restricted, else Internal
        if c >= 2:
            return "Restricted"
        return "Internal"

    def _reasoning_for_column(
        self,
        cname: str,
        name_types: List[str],
        pat_freqs: Dict[str, float],
        stats_score: float,
        coarse: str,
    ) -> str:
        parts = []
        if name_types:
            parts.append(f"Name cues ({cname}) matched: {', '.join(sorted(set(name_types)))}")
        strong = {k: v for k, v in pat_freqs.items() if v >= 0.1}
        if strong:
            parts.append("Pattern matches >=10%: " + ", ".join([f"{k}:{v}" for k, v in strong.items()]))
        if stats_score >= 0.7:
            parts.append("Statistical profile suggests identifiers (high uniqueness/entropy)")
        elif stats_score > 0:
            parts.append("Some statistical signals present")
        parts.append(f"Mapped to type: {coarse}")
        return "; ".join(parts)

    # ---------------- Utilities ----------------
    def _split_fqn_flexible(self, name: str) -> Tuple[str, str, str]:
        parts = (name or "").split(".")
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
        if len(parts) == 2:
            return parts[0], parts[0], parts[1]
        return "VIRTUAL_DB", "PUBLIC", parts[0]

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        from collections import Counter
        c = Counter(s)
        n = float(len(s))
        return -sum((cnt / n) * math.log2(cnt / n) for cnt in c.values())

    @staticmethod
    def _as_text(v: Any) -> str:
        if v is None:
            return ""
        try:
            return str(v)
        except Exception:
            return ""

    def _build_patterns(self) -> Dict[str, Any]:
        # Reuse AI service patterns to avoid duplication
        return self.ai._sensitivity_patterns()


internal_sensitive_engine = InternalSensitiveEngine()
