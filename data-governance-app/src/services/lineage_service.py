"""
Lineage service: fetches lineage graph, impact, quality metrics, and basic risk scoring.
"""
from __future__ import annotations
import typing as t
import pandas as pd
from dataclasses import dataclass
import re

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings


@dataclass
class LineageFilters:
    root: str | None = None
    depth: int = 2
    direction: str = "both"  # "upstream", "downstream", "both"
    classification: list[str] | None = None
    risk_levels: list[str] | None = None
    quality_dims: list[str] | None = None
    owner: str | None = None
    custodian: str | None = None
    transform_types: list[str] | None = None
    issue_status: list[str] | None = None
    time_range: str | None = None  # "24h", "7d", "30d", "90d"


class lineage_service:
    @staticmethod
    def get_edges(root: str | None = None, depth: int = 2, direction: str = "both") -> pd.DataFrame:
        """Return lineage edges (SRC -> TGT). Best-effort using INFORMATION_SCHEMA.OBJECT_DEPENDENCIES.
        Columns: SRC_FULL_NAME, TGT_FULL_NAME, RELATIONSHIP, LAST_ALTERED
        """
        db = settings.SNOWFLAKE_DATABASE
        try:
            # OBJECT_DEPENDENCIES only for views & materialized views referencing base objects
            q = f"""
                SELECT
                  UPPER(REFERENCING_OBJECT_DATABASE)||'.'||UPPER(REFERENCING_OBJECT_SCHEMA)||'.'||UPPER(REFERENCING_OBJECT_NAME) AS SRC_FULL_NAME,
                  UPPER(REFERENCED_OBJECT_DATABASE)||'.'||UPPER(REFERENCED_OBJECT_SCHEMA)||'.'||UPPER(REFERENCED_OBJECT_NAME) AS TGT_FULL_NAME,
                  REFERENCED_OBJECT_DOMAIN AS RELATIONSHIP,
                  CURRENT_TIMESTAMP() AS LAST_ALTERED
                FROM {db}.INFORMATION_SCHEMA.OBJECT_DEPENDENCIES
            """
            rows = snowflake_connector.execute_query(q) or []
            df = pd.DataFrame(rows)
            if not df.empty:
                # In dependencies, SRC depends on TGT (SRC -> TGT). For downstream, invert as needed in page.
                return df
        except Exception:
            pass
        # Fallback: empty DataFrame
        return pd.DataFrame(columns=["SRC_FULL_NAME","TGT_FULL_NAME","RELATIONSHIP","LAST_ALTERED"])

    @staticmethod
    def get_asset_metadata(full_names: list[str]) -> pd.DataFrame:
        if not full_names:
            return pd.DataFrame()
        db = settings.SNOWFLAKE_DATABASE
        try:
            # Prefer inventory if available
            q = f"""
                SELECT FULL_NAME, COALESCE(DATA_CLASSIFICATION,'Unclassified') AS DATA_CLASSIFICATION,
                       COALESCE(C,0) AS C, COALESCE(I,0) AS I, COALESCE(A,0) AS A,
                       COALESCE(BUSINESS_UNIT, SPLIT_PART(FULL_NAME,'.',2)) AS BU,
                       OWNER, CUSTODIAN, UPDATED_AT AS LAST_UPDATED_AT
                FROM {db}.DATA_GOVERNANCE.ASSET_INVENTORY
                WHERE FULL_NAME IN ({','.join(['%s']*len(full_names))})
            """
            rows = snowflake_connector.execute_query(q, tuple(full_names)) or []
            return pd.DataFrame(rows)
        except Exception:
            return pd.DataFrame({
                "FULL_NAME": full_names,
                "DATA_CLASSIFICATION": ["Unclassified"]*len(full_names),
                "C": [0]*len(full_names),
                "I": [0]*len(full_names),
                "A": [0]*len(full_names),
                "BU": [None]*len(full_names),
                "OWNER": [None]*len(full_names),
                "CUSTODIAN": [None]*len(full_names),
                "LAST_UPDATED_AT": [None]*len(full_names),
            })

    @staticmethod
    def get_quality(full_names: list[str]) -> pd.DataFrame:
        if not full_names:
            return pd.DataFrame()
        db = settings.SNOWFLAKE_DATABASE
        try:
            q = f"""
                SELECT FULL_NAME, DIMENSION, SCORE, MEASURE_AT, SLA_STATUS, ISSUE_STATUS
                FROM {db}.DATA_GOVERNANCE.QUALITY_METRICS
                WHERE FULL_NAME IN ({','.join(['%s']*len(full_names))})
            """
            rows = snowflake_connector.execute_query(q, tuple(full_names)) or []
            return pd.DataFrame(rows)
        except Exception:
            return pd.DataFrame(columns=["FULL_NAME","DIMENSION","SCORE","MEASURE_AT","SLA_STATUS","ISSUE_STATUS"])

    @staticmethod
    def compute_risk(meta: pd.DataFrame, edges: pd.DataFrame, quality: pd.DataFrame) -> pd.DataFrame:
        """Simple heuristic risk score 0..100 using CIA, degree, and quality issues."""
        if meta is None or meta.empty:
            return pd.DataFrame()
        m = meta.copy()
        # Degree (fan-out) from edges (downstream exposure)
        deg = {}
        try:
            if edges is not None and not edges.empty:
                for src in edges.get("SRC_FULL_NAME", []):
                    deg[src] = deg.get(src, 0) + 1
        except Exception:
            pass
        m["DEGREE"] = m["FULL_NAME"].map(lambda x: deg.get(x, 0)) if "FULL_NAME" in m.columns else 0
        # Quality penalty: number of issues with low score (<70) or ISSUE_STATUS in [Open, In-progress]
        qpen = {}
        try:
            if quality is not None and not quality.empty:
                qg = quality.groupby("FULL_NAME").apply(lambda g: int(((pd.to_numeric(g.get("SCORE"), errors='coerce') < 70).sum()) + ((g.get("ISSUE_STATUS").astype(str).isin(["Open","In-progress"]).sum())))).to_dict()
                qpen.update(qg)
        except Exception:
            pass
        m["Q_PEN"] = m["FULL_NAME"].map(lambda x: qpen.get(x, 0))
        # CIA severity
        def _sev(row):
            try:
                return max(int(row.get("C",0)), int(row.get("I",0)), int(row.get("A",0)))
            except Exception:
                return 0
        m["CIA_SEV"] = m.apply(_sev, axis=1)
        # Score formula
        m["RISK_SCORE"] = (m["CIA_SEV"]*20 + m["DEGREE"].astype(int)*5 + m["Q_PEN"].astype(int)*10).clip(upper=100)
        return m[["FULL_NAME","RISK_SCORE","CIA_SEV","DEGREE","Q_PEN","DATA_CLASSIFICATION","C","I","A","BU","OWNER","CUSTODIAN","LAST_UPDATED_AT"]]

    @staticmethod
    def downstream_impact(full_name: str, edges: pd.DataFrame, depth: int = 2) -> list[str]:
        if edges is None or edges.empty or not full_name:
            return []
        graph = {}
        for _, r in edges.iterrows():
            graph.setdefault(str(r["SRC_FULL_NAME"]), []).append(str(r["TGT_FULL_NAME"]))
        seen = set()
        out = []
        def dfs(node: str, d: int):
            if d < 0:
                return
            for nb in graph.get(node, []):
                if nb not in seen:
                    seen.add(nb)
                    out.append(nb)
                    dfs(nb, d-1)
        dfs(full_name, depth)
        return out

    @staticmethod
    def get_change_events(full_names: list[str], time_range: str = "7d", limit: int = 500) -> pd.DataFrame:
        """Return recent DDL change events for the given objects from ACCOUNT_USAGE.QUERY_HISTORY.
        Best-effort heuristic that searches for CREATE/ALTER/DROP touching the object names.
        Columns: FULL_NAME, EVENT, USER_NAME, START_TIME, QUERY_TEXT
        time_range: one of ["24h","7d","30d","90d"]
        """
        if not full_names:
            return pd.DataFrame(columns=["FULL_NAME","EVENT","USER_NAME","START_TIME","QUERY_TEXT"])
        try:
            tr_map = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}
            days = tr_map.get(str(time_range), 7)
            # Build simple OR pattern for object names; cap number to avoid overly large query
            names = [str(x).upper() for x in full_names[:200]]
            # Use CONTAINS for each name in QUERY_TEXT; Snowflake supports ILIKE but ACCOUNT_USAGE requires double quotes in columns
            predicates = " OR ".join([f"QUERY_TEXT ILIKE '%' || %(n{i})s || '%'" for i, _ in enumerate(names)])
            params = {f"n{i}": n for i, n in enumerate(names)}
            sql = f"""
                SELECT 
                  USER_NAME, START_TIME, QUERY_TEXT
                FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                WHERE START_TIME > DATEADD('day', -{int(days)}, CURRENT_TIMESTAMP())
                  AND (QUERY_TEXT ILIKE 'CREATE %' OR QUERY_TEXT ILIKE 'ALTER %' OR QUERY_TEXT ILIKE 'DROP %')
                  AND ({predicates})
                ORDER BY START_TIME DESC
                LIMIT %(lim)s
            """
            params["lim"] = int(limit)
            rows = snowflake_connector.execute_query(sql, params) or []
            # Extract object name matches back to FULL_NAME best-effort by exact match presence
            out_rows: list[dict] = []
            for r in rows:
                qt = str(r.get("QUERY_TEXT") or "")
                evt = ("CREATE" if qt.upper().startswith("CREATE") else ("ALTER" if qt.upper().startswith("ALTER") else ("DROP" if qt.upper().startswith("DROP") else "DDL")))
                matched = None
                up = qt.upper()
                for n in names:
                    if n in up:
                        matched = n
                        break
                out_rows.append({
                    "FULL_NAME": matched,
                    "EVENT": evt,
                    "USER_NAME": r.get("USER_NAME"),
                    "START_TIME": r.get("START_TIME"),
                    "QUERY_TEXT": r.get("QUERY_TEXT"),
                })
            df = pd.DataFrame(out_rows)
            return df
        except Exception:
            return pd.DataFrame(columns=["FULL_NAME","EVENT","USER_NAME","START_TIME","QUERY_TEXT"])

    @staticmethod
    def ai_recommendations(meta: pd.DataFrame, edges: pd.DataFrame, quality: pd.DataFrame, risk_df: pd.DataFrame | None = None) -> pd.DataFrame:
        """Generate lightweight, rule-based recommendations based on CIA, lineage fan-out, and quality issues.
        Columns: FULL_NAME, RECOMMENDATION, SEVERITY, RATIONALE
        """
        if meta is None or meta.empty:
            return pd.DataFrame(columns=["FULL_NAME","RECOMMENDATION","SEVERITY","RATIONALE"])

    @staticmethod
    def get_object_columns(full_names: list[str]) -> pd.DataFrame:
        """Fetch columns for the given objects from INFORMATION_SCHEMA.COLUMNS and enrich with tag hits when available.
        Returns columns: FULL_NAME, COLUMN_NAME, DATA_TYPE, TAGS (optional)
        """
        if not full_names:
            return pd.DataFrame(columns=["FULL_NAME","COLUMN_NAME","DATA_TYPE","TAGS"])
        db = settings.SNOWFLAKE_DATABASE
        try:
            preds = []
            params = {}
            for i, fn in enumerate(full_names[:300]):
                try:
                    d, s, t = fn.split('.')
                except ValueError:
                    continue
                preds.append(f"(TABLE_CATALOG = %(db{i})s AND TABLE_SCHEMA = %(s{i})s AND TABLE_NAME = %(t{i})s)")
                params[f"db{i}"] = d
                params[f"s{i}"] = s
                params[f"t{i}"] = t
            if not preds:
                return pd.DataFrame(columns=["FULL_NAME","COLUMN_NAME","DATA_TYPE","TAGS"])
            rows = snowflake_connector.execute_query(
                f"""
                SELECT TABLE_CATALOG||'.'||TABLE_SCHEMA||'.'||TABLE_NAME AS FULL_NAME,
                       COLUMN_NAME, DATA_TYPE
                FROM {db}.INFORMATION_SCHEMA.COLUMNS
                WHERE {' OR '.join(preds)}
                ORDER BY FULL_NAME, ORDINAL_POSITION
                """,
                params,
            ) or []
        except Exception:
            rows = []
        df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["FULL_NAME","COLUMN_NAME","DATA_TYPE"])
        # Attach tag strings when possible (best-effort)
        try:
            tags = snowflake_connector.execute_query(
                """
                SELECT 
                  UPPER(OBJECT_DATABASE)||'.'||UPPER(OBJECT_SCHEMA)||'.'||UPPER(OBJECT_NAME) AS FULL_NAME,
                  UPPER(COLUMN_NAME) AS COLUMN_NAME,
                  TAG_NAME, TAG_VALUE
                FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                WHERE COLUMN_NAME IS NOT NULL
                """
            ) or []
            if tags and not df.empty:
                tdf = pd.DataFrame(tags)
                tdf["TAG_PAIR"] = tdf.apply(lambda r: f"{r.get('TAG_NAME')}={r.get('TAG_VALUE')}", axis=1)
                grouped = tdf.groupby(["FULL_NAME","COLUMN_NAME"])['TAG_PAIR'].apply(lambda x: ", ".join(sorted(set([str(v) for v in x if v])))).reset_index().rename(columns={"TAG_PAIR":"TAGS"})
                # Normalize case to upper for join on columns
                df["COLUMN_NAME_UP"] = df["COLUMN_NAME"].astype(str).str.upper()
                out = df.merge(grouped, how='left', left_on=["FULL_NAME","COLUMN_NAME_UP"], right_on=["FULL_NAME","COLUMN_NAME"]).drop(columns=["COLUMN_NAME_y","COLUMN_NAME_UP"]).rename(columns={"COLUMN_NAME_x":"COLUMN_NAME"})
                out["TAGS"] = out["TAGS"].fillna("")
                return out
        except Exception:
            pass
        # Ensure TAGS column
        if not df.empty and "TAGS" not in df.columns:
            df["TAGS"] = ""
        return df

    @staticmethod
    def get_streams_tasks(full_names: list[str], time_range: str = "30d", limit: int = 200) -> pd.DataFrame:
        """Best-effort lookup of Snowflake Streams and Tasks related to the given objects.
        Returns columns: TYPE (STREAM|TASK|PIPE), NAME, DATABASE, SCHEMA, TARGET, LAST_ALTERED, STATE/COMMENT when available.
        """
        if not full_names:
            return pd.DataFrame(columns=["TYPE","NAME","DATABASE","SCHEMA","TARGET","LAST_ALTERED","STATE","COMMENT"])
        db = settings.SNOWFLAKE_DATABASE
        try:
            # Streams
            streams = snowflake_connector.execute_query(
                f"""
                SELECT 'STREAM' AS TYPE, STREAM_NAME AS NAME, TABLE_CATALOG AS DATABASE, TABLE_SCHEMA AS SCHEMA,
                       TABLE_CATALOG||'.'||TABLE_SCHEMA||'.'||TABLE_NAME AS TARGET,
                       CREATED AS LAST_ALTERED, COMMENT
                FROM {db}.INFORMATION_SCHEMA.STREAMS
                WHERE TABLE_CATALOG||'.'||TABLE_SCHEMA||'.'||TABLE_NAME IN ({','.join(['%s']*len(full_names))})
                """,
                tuple(full_names),
            ) or []
        except Exception:
            streams = []
        try:
            # Tasks
            tasks = snowflake_connector.execute_query(
                f"""
                SELECT 'TASK' AS TYPE, TASK_NAME AS NAME, DATABASE_NAME AS DATABASE, SCHEMA_NAME AS SCHEMA,
                       SCHEDULE, STATE, COMMENT, LAST_ALTERED
                FROM {db}.INFORMATION_SCHEMA.TASKS
                WHERE DATABASE_NAME||'.'||SCHEMA_NAME||'.'||TASK_NAME IS NOT NULL
                ORDER BY LAST_ALTERED DESC
                LIMIT %(lim)s
                """,
                {"lim": int(limit)},
            ) or []
        except Exception:
            tasks = []
        # Pipes (optional)
        try:
            pipes = snowflake_connector.execute_query(
                f"""
                SELECT 'PIPE' AS TYPE, PIPE_NAME AS NAME, DATABASE_NAME AS DATABASE, SCHEMA_NAME AS SCHEMA,
                       DEFINITION AS COMMENT, LAST_ALTERED
                FROM {db}.INFORMATION_SCHEMA.PIPES
                ORDER BY LAST_ALTERED DESC
                LIMIT %(lim)s
                """,
                {"lim": int(limit)},
            ) or []
        except Exception:
            pipes = []
        df = pd.DataFrame(streams + tasks + pipes)
        return df

    @staticmethod
    def compute_overview_kpis(edges: pd.DataFrame, meta: pd.DataFrame) -> dict:
        """Compute high-level KPIs for overview cards.
        - total_sources: count of nodes with in-degree=0
        - total_targets: count of nodes with out-degree=0
        - upstream_downstream_dependencies: total unique edges and average degree
        - sensitive_flows: edges where either endpoint is Restricted/Confidential
        - compliance_coverage: % nodes with classification not Unclassified
        - unclassified_flows: number of edges where any endpoint is Unclassified
        """
        nodes = set()
        if edges is not None and not edges.empty:
            nodes.update(edges['SRC_FULL_NAME'].astype(str).tolist())
            nodes.update(edges['TGT_FULL_NAME'].astype(str).tolist())
        indeg = {}
        outdeg = {}
        for _, r in (edges.iterrows() if edges is not None and not edges.empty else []):
            s = str(r['SRC_FULL_NAME']); t = str(r['TGT_FULL_NAME'])
            outdeg[s] = outdeg.get(s, 0) + 1
            indeg[t] = indeg.get(t, 0) + 1
        total_sources = sum(1 for n in nodes if indeg.get(n, 0) == 0)
        total_targets = sum(1 for n in nodes if outdeg.get(n, 0) == 0)
        total_edges = int(len(edges)) if edges is not None and not edges.empty else 0
        avg_degree = (total_edges * 2 / max(1, len(nodes))) if nodes else 0.0
        # Classification maps
        cls_map = {}
        if meta is not None and not meta.empty:
            m2 = meta.copy(); m2['DATA_CLASSIFICATION'] = m2['DATA_CLASSIFICATION'].fillna('Unclassified')
            cls_map = dict(zip(m2['FULL_NAME'], m2['DATA_CLASSIFICATION']))
        def _is_sensitive(n):
            c = (cls_map.get(n) or 'Unclassified').lower()
            return c in ('restricted','confidential')
        def _is_unclassified(n):
            c = (cls_map.get(n) or 'Unclassified').lower()
            return c == 'unclassified'
        sensitive_flows = 0
        unclassified_flows = 0
        if edges is not None and not edges.empty:
            for _, r in edges.iterrows():
                s = str(r['SRC_FULL_NAME']); t = str(r['TGT_FULL_NAME'])
                if _is_sensitive(s) or _is_sensitive(t):
                    sensitive_flows += 1
                if _is_unclassified(s) or _is_unclassified(t):
                    unclassified_flows += 1
        classified_nodes = sum(1 for n in nodes if not _is_unclassified(n)) if nodes else 0
        compliance_coverage = (classified_nodes / len(nodes) * 100.0) if nodes else 0.0
        return {
            'total_sources': total_sources,
            'total_targets': total_targets,
            'total_edges': total_edges,
            'avg_degree': round(avg_degree, 2),
            'sensitive_flows': sensitive_flows,
            'compliance_coverage': round(compliance_coverage, 1),
            'unclassified_flows': unclassified_flows,
            'node_count': len(nodes)
        }
        try:
            recs: list[dict] = []
            # Build helpers
            deg = {}
            try:
                if edges is not None and not edges.empty:
                    for src in edges.get("SRC_FULL_NAME", []):
                        deg[src] = deg.get(src, 0) + 1
            except Exception:
                pass
            qpen = {}
            try:
                if quality is not None and not quality.empty:
                    qg = quality.groupby("FULL_NAME").apply(lambda g: int(((pd.to_numeric(g.get("SCORE"), errors='coerce') < 70).sum()) + ((g.get("ISSUE_STATUS").astype(str).isin(["Open","In-progress"]).sum())))).to_dict()
                    qpen.update(qg)
            except Exception:
                pass
            risk_map = {}
            if risk_df is not None and not risk_df.empty and "RISK_SCORE" in risk_df.columns:
                risk_map = dict(zip(risk_df["FULL_NAME"], risk_df["RISK_SCORE"]))

            for _, row in meta.iterrows():
                full = row.get("FULL_NAME")
                if not full:
                    continue
                c = int(pd.to_numeric(row.get("C"), errors='coerce') or 0)
                i = int(pd.to_numeric(row.get("I"), errors='coerce') or 0)
                a = int(pd.to_numeric(row.get("A"), errors='coerce') or 0)
                severity = max(c, i, a)
                fanout = int(deg.get(full, 0))
                q = int(qpen.get(full, 0))
                risk = int(pd.to_numeric(risk_map.get(full, 0), errors='coerce') or 0)
                cls = str(row.get("DATA_CLASSIFICATION") or "Unclassified")

                # Rule 1: High severity + broad downstream exposure
                if severity >= 3 and fanout >= 2:
                    recs.append({
                        "FULL_NAME": full,
                        "RECOMMENDATION": "Enforce masking or limit downstream access",
                        "SEVERITY": "Critical" if risk >= 80 else ("High" if risk >= 60 else "High"),
                        "RATIONALE": f"CIA severity={severity}, downstream degree={fanout}, classification={cls}"
                    })

                # Rule 2: Quality issues present
                if q > 0:
                    recs.append({
                        "FULL_NAME": full,
                        "RECOMMENDATION": "Open QA review and address data quality issues",
                        "SEVERITY": "High" if q >= 3 else "Medium",
                        "RATIONALE": f"Detected {q} quality issue signals"
                    })

                # Rule 3: Unclassified but connected to sensitive neighbors (propagation risk)
                try:
                    if (cls.lower() == "unclassified") and edges is not None and not edges.empty:
                        # If any neighbor has Restricted/Confidential classification
                        neighbors = set()
                        nbrs_src = edges[edges["SRC_FULL_NAME"] == full]["TGT_FULL_NAME"].astype(str).tolist()
                        nbrs_tgt = edges[edges["TGT_FULL_NAME"] == full]["SRC_FULL_NAME"].astype(str).tolist()
                        neighbors.update(nbrs_src + nbrs_tgt)
                        if not meta.empty and "FULL_NAME" in meta.columns:
                            m2 = meta.set_index("FULL_NAME")
                            for nb in neighbors:
                                if nb in m2.index:
                                    ncls = str(m2.loc[nb].get("DATA_CLASSIFICATION") or "").lower()
                                    if ncls in ("restricted","confidential"):
                                        recs.append({
                                            "FULL_NAME": full,
                                            "RECOMMENDATION": "Review and classify due to sensitive neighbors",
                                            "SEVERITY": "Medium",
                                            "RATIONALE": f"Neighbor {nb} has classification {ncls}"
                                        })
                                        break
                except Exception:
                    pass

                # Rule 4: Missing owner for sensitive assets
                if severity >= 2 and not (row.get("OWNER") or ""):
                    recs.append({
                        "FULL_NAME": full,
                        "RECOMMENDATION": "Assign a Data Owner",
                        "SEVERITY": "High" if severity >= 3 else "Medium",
                        "RATIONALE": "Sensitive asset missing OWNER"
                    })

            df = pd.DataFrame(recs)
            if not df.empty:
                # Deduplicate recommendations by FULL_NAME+RECOMMENDATION
                df = df.drop_duplicates(subset=["FULL_NAME","RECOMMENDATION"]) 
            return df
        except Exception:
            return pd.DataFrame(columns=["FULL_NAME","RECOMMENDATION","SEVERITY","RATIONALE"])

    @staticmethod
    def _get_view_text(full_name: str) -> str | None:
        """Return the view text from INFORMATION_SCHEMA.VIEWS for the given object.
        Expects full_name = DB.SCHEMA.VIEW_NAME
        """
        if not full_name:
            return None
        try:
            db, sch, name = full_name.split('.')
        except ValueError:
            return None
        try:
            rows = snowflake_connector.execute_query(
                f"""
                SELECT TEXT
                FROM {db}.INFORMATION_SCHEMA.VIEWS
                WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                LIMIT 1
                """,
                {"s": sch, "t": name},
            ) or []
            return rows[0].get('TEXT') if rows else None
        except Exception:
            return None

    @staticmethod
    def derive_column_lineage(full_name: str) -> pd.DataFrame:
        """Best-effort column lineage for a VIEW by parsing its SELECT list.
        Returns columns: TARGET_COLUMN, SOURCE_ASSET, SOURCE_COLUMN, TRANSFORM
        Handles: simple SELECTs, aliases, table-qualified cols, basic functions, and basic CTE/nested SELECTs.
        """
        txt = lineage_service._get_view_text(full_name)
        if not txt:
            return pd.DataFrame(columns=["FULL_NAME","TARGET_COLUMN","SOURCE_ASSET","SOURCE_COLUMN","TRANSFORM"])
        sql = str(txt)
        # Normalize whitespace (preserve parentheses for parsing)
        s = re.sub(r"\s+", " ", sql, flags=re.MULTILINE).strip()

        # --- Helpers for CTE and alias extraction ---
        def _extract_ctes(query: str) -> tuple[dict[str,str], str]:
            q = query.strip()
            ctes: dict[str,str] = {}
            if not q.upper().startswith("WITH "):
                return ctes, q
            i = q.upper().find("WITH ")
            pos = i + 5
            name = ""; buf = ""; depth = 0; state = 'name'
            while pos < len(q):
                ch = q[pos]
                if state == 'name':
                    if ch == ' ':
                        pos += 1; continue
                    m = re.match(r"([A-Za-z_][\w]*)", q[pos:])
                    if not m:
                        break
                    name = m.group(1)
                    pos += len(name)
                    m2 = re.match(r"\s*AS\s*\(", q[pos:], flags=re.IGNORECASE)
                    if not m2:
                        break
                    pos += m2.end()
                    state = 'subq'
                    depth = 1
                    buf = ""
                elif state == 'subq':
                    if ch == '(':
                        depth += 1
                    elif ch == ')':
                        depth -= 1
                        if depth == 0:
                            ctes[name.upper()] = buf.strip()
                            pos += 1
                            m3 = re.match(r"\s*,", q[pos:])
                            if m3:
                                pos += m3.end(); state = 'name'; continue
                            else:
                                main_sql = q[pos:].strip()
                                return ctes, main_sql
                    buf += ch
                    pos += 1
            return ctes, q

        def _alias_map_for_sql(query: str, ctes: dict[str,str]) -> dict[str,str]:
            amap: dict[str,str] = {}
            try:
                from_pat = re.compile(r'FROM\s+([\w\.\"]+)(?:\s+AS)?\s+(\w+)', re.IGNORECASE)
                join_pat = re.compile(r'JOIN\s+([\w\.\"]+)(?:\s+AS)?\s+(\w+)', re.IGNORECASE)
                def _resolve(obj: str) -> str:
                    o = obj.replace('"','').upper()
                    if o in ctes:
                        sub_ctes, sub_main = _extract_ctes(ctes[o])
                        mm = from_pat.search(sub_main) or join_pat.search(sub_main)
                        if mm:
                            return _resolve(mm.group(1))
                        return o
                    return o
                for m in from_pat.finditer(query):
                    amap[m.group(2)] = _resolve(m.group(1))
                for m in join_pat.finditer(query):
                    amap[m.group(2)] = _resolve(m.group(1))
            except Exception:
                pass
            return amap

        def _split_select_list(sel: str) -> list[str]:
            parts: list[str] = []
            buf = ""; depth = 0
            for ch in sel:
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth = max(0, depth - 1)
                if ch == ',' and depth == 0:
                    parts.append(buf.strip()); buf = ""
                else:
                    buf += ch
            if buf.strip():
                parts.append(buf.strip())
            return parts

        def _resolve_source(expr: str, alias_map: dict[str,str], cte_map: dict[str,str]) -> tuple[str|None, str|None]:
            qexpr = expr.strip().strip('()')
            mcol = re.search(r"(\w+)\.(\w+)", qexpr)
            if mcol:
                al = mcol.group(1)
                col = mcol.group(2).upper()
                base = alias_map.get(al, al).upper()
                if base in cte_map:
                    sub_ctes, sub_main = _extract_ctes(cte_map[base])
                    sub_alias = _alias_map_for_sql(sub_main, sub_ctes)
                    mm = re.search(rf"\b(\w+)\.{col}\b", sub_main, flags=re.IGNORECASE)
                    if mm:
                        return sub_alias.get(mm.group(1), base), col
                return base, col
            mcol2 = re.search(r"^([A-Za-z_][\w]*)$", qexpr)
            if mcol2 and len(alias_map) == 1:
                base = list(alias_map.values())[0]
                return base, mcol2.group(1).upper()
            return None, None

        # Parse CTEs and main SELECT
        cte_map, main_sql = _extract_ctes(s)
        msel = re.search(r"SELECT\s+(.*?)\s+FROM\s", main_sql, flags=re.IGNORECASE | re.DOTALL)
        if not msel:
            return pd.DataFrame(columns=["FULL_NAME","TARGET_COLUMN","SOURCE_ASSET","SOURCE_COLUMN","TRANSFORM"])
        sel_list = msel.group(1)
        alias_map = _alias_map_for_sql(main_sql, cte_map)
        parts = _split_select_list(sel_list)

        rows = []
        for expr in parts:
            alias_match = re.search(r"\s+AS\s+([\w\"]+)$", expr, flags=re.IGNORECASE)
            if alias_match:
                tgt = alias_match.group(1).replace('"','')
                src_expr = expr[:alias_match.start()].strip()
            else:
                m2 = re.search(r"\s+([\w\"]+)$", expr)
                if m2 and '.' not in m2.group(1):
                    tgt = m2.group(1).replace('"','')
                    src_expr = expr[:m2.start()].strip()
                else:
                    tgt = expr.replace('"','')
                    src_expr = expr
            base, col = _resolve_source(src_expr, alias_map, cte_map)
            qshort = src_expr if len(src_expr) < 300 else (src_expr[:297] + '...')
            rows.append({
                "FULL_NAME": full_name,
                "TARGET_COLUMN": str(tgt).upper(),
                "SOURCE_ASSET": (base.upper() if isinstance(base, str) else base),
                "SOURCE_COLUMN": (col.upper() if isinstance(col, str) else col),
                "TRANSFORM": qshort
            })
        return pd.DataFrame(rows)

    @staticmethod
    def get_object_info(full_names: list[str]) -> pd.DataFrame:
        """Return object info for TABLES and VIEWS: FULL_NAME, OBJECT_TYPE, CREATED, LAST_ALTERED.
        Best-effort union of INFORMATION_SCHEMA.TABLES and VIEWS.
        """
        if not full_names:
            return pd.DataFrame(columns=["FULL_NAME","OBJECT_TYPE","CREATED","LAST_ALTERED"])
        db = settings.SNOWFLAKE_DATABASE
        try:
            parts = [fn.split('.') for fn in full_names[:500] if isinstance(fn, str) and fn.count('.')==2]
            if not parts:
                return pd.DataFrame(columns=["FULL_NAME","OBJECT_TYPE","CREATED","LAST_ALTERED"])
            preds = []
            params = {}
            for i,(d,s,t) in enumerate(parts):
                preds.append(f"(TABLE_CATALOG=%(d{i})s AND TABLE_SCHEMA=%(s{i})s AND TABLE_NAME=%(t{i})s)")
                params[f"d{i}"] = d; params[f"s{i}"] = s; params[f"t{i}"] = t
            sql = f"""
                WITH T AS (
                  SELECT TABLE_CATALOG||'.'||TABLE_SCHEMA||'.'||TABLE_NAME AS FULL_NAME,
                         'TABLE' AS OBJECT_TYPE, CREATED, LAST_ALTERED
                  FROM {db}.INFORMATION_SCHEMA.TABLES
                  WHERE {' OR '.join(preds)}
                ), V AS (
                  SELECT TABLE_CATALOG||'.'||TABLE_SCHEMA||'.'||TABLE_NAME AS FULL_NAME,
                         'VIEW' AS OBJECT_TYPE, CREATED, LAST_ALTERED
                  FROM {db}.INFORMATION_SCHEMA.VIEWS
                  WHERE {' OR '.join(preds)}
                )
                SELECT * FROM T UNION ALL SELECT * FROM V
            """
            rows = snowflake_connector.execute_query(sql, params) or []
            return pd.DataFrame(rows)
        except Exception:
            return pd.DataFrame(columns=["FULL_NAME","OBJECT_TYPE","CREATED","LAST_ALTERED"])

    @staticmethod
    def get_special_categories(full_names: list[str]) -> pd.DataFrame:
        """Return special category hits (PII, PCI, HIPAA, Financial) for assets or their columns.
        Columns: FULL_NAME, CATEGORIES (comma-separated)
        """
        if not full_names:
            return pd.DataFrame(columns=["FULL_NAME","CATEGORIES"])
        cats = {"PII","PCI","HIPAA","FINANCIAL"}
        try:
            names = [str(x).upper() for x in full_names[:800]]
            rows = snowflake_connector.execute_query(
                """
                SELECT UPPER(OBJECT_DATABASE)||'.'||UPPER(OBJECT_SCHEMA)||'.'||UPPER(OBJECT_NAME) AS FULL_NAME,
                       UPPER(COALESCE(TAG_NAME,'')||'='||COALESCE(TAG_VALUE,'')) AS TV
                FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                WHERE OBJECT_DATABASE IS NOT NULL
                """
            ) or []
            if not rows:
                return pd.DataFrame(columns=["FULL_NAME","CATEGORIES"])
            df = pd.DataFrame(rows)
            df = df[df['FULL_NAME'].isin(names)]
            def _extract(tv: str):
                u = str(tv or '').upper()
                hits = [c for c in cats if c in u]
                return hits
            g = df.groupby('FULL_NAME')['TV'].apply(lambda s: sorted({h for tv in s for h in _extract(tv)})).reset_index()
            g['CATEGORIES'] = g['TV'].apply(lambda lst: ", ".join(lst))
            return g[['FULL_NAME','CATEGORIES']]
        except Exception:
            return pd.DataFrame(columns=["FULL_NAME","CATEGORIES"])

    @staticmethod
    def derive_transform_types(full_name: str) -> list[str]:
        """Infer simple transformation types from a VIEW's SQL: Aggregation, Join, Filter, Calculation.
        Returns a list of types present.
        """
        txt = lineage_service._get_view_text(full_name)
        if not txt:
            return []
        s = re.sub(r"\s+", " ", str(txt)).upper()
        types: list[str] = []
        try:
            if ' GROUP BY ' in s or ' SUM(' in s or ' AVG(' in s or ' COUNT(' in s:
                types.append('Aggregation')
            if ' JOIN ' in s:
                types.append('Join')
            if ' WHERE ' in s or ' QUALIFY ' in s or ' HAVING ' in s:
                types.append('Filter')
            # Calculation: presence of arithmetic or function on columns
            if re.search(r"[\+\-\*/]\s*\w|\bCAST\(|\bCOALESCE\(|\bNVL\(|\bCASE\s+WHEN\b", s):
                types.append('Calculation')
        except Exception:
            pass
        return sorted(set(types))
