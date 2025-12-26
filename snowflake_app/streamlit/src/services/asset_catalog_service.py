from typing import List, Optional, Dict, Any, Tuple
import json
from datetime import datetime
import math
import re
import logging
try:
    import numpy as _np  # optional
except Exception:
    _np = None  # type: ignore

from src.connectors.snowflake_connector import snowflake_connector

logger = logging.getLogger(__name__)

class MetadataCatalogService:
    def migrate_assets_table(self, database: str) -> None:
        """Evolve ASSETS table schema to include BUSINESS_UNIT and REGULATORY columns."""
        schema = "DATA_CLASSIFICATION_GOVERNANCE"
        table = "ASSETS"
        fqn = f"{database}.{schema}.{table}"
        try:
            cols = {r['COLUMN_NAME'] for r in self._q(f"SELECT COLUMN_NAME FROM {database}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='{schema}' AND TABLE_NAME='{table}'")}
            if 'BUSINESS_UNIT' not in cols:
                self._x(f"ALTER TABLE {fqn} ADD COLUMN BUSINESS_UNIT STRING")
            if 'REGULATORY' not in cols:
                self._x(f"ALTER TABLE {fqn} ADD COLUMN REGULATORY STRING")
            
            # Backfill logic based on naming conventions and tags
            self._x(f"""
                UPDATE {fqn} 
                SET BUSINESS_UNIT = CASE 
                    WHEN ASSET_NAME LIKE 'FIN%%' THEN 'Finance'
                    WHEN ASSET_NAME LIKE 'HR%%' THEN 'HR'
                    WHEN ASSET_NAME LIKE 'SALES%%' THEN 'Sales'
                    ELSE 'General'
                END
                WHERE BUSINESS_UNIT IS NULL
            """)
            self._x(f"""
                UPDATE {fqn}
                SET REGULATORY = CASE
                    WHEN ASSET_NAME LIKE '%%PII%%' THEN 'GDPR'
                    WHEN ASSET_NAME LIKE '%%SOX%%' THEN 'SOX'
                    ELSE 'Internal'
                END
                WHERE REGULATORY IS NULL
            """)
        except Exception as e:
            logger.error(f"Migration failed for {fqn}: {e}")

    def get_filter_context(self) -> Dict[str, Any]:
        """Resolves active filters from session state."""
        import streamlit as st
        return {
            "database": st.session_state.get("active_database"),
            "schema": st.session_state.get("active_schema"),
            "warehouse": st.session_state.get("active_warehouse"),
            "label": st.session_state.get("active_label"),
            "owner": st.session_state.get("active_owner"),
        }

    def resolve_fqn(self, db: str, sc: str, obj: str) -> str:
        return f'"{db}"."{sc}"."{obj}"'

    def parse_fqn(self, fqn: str) -> Tuple[str, str, str]:
        parts = fqn.split('.')
        if len(parts) == 3:
            return parts[0].strip('"'), parts[1].strip('"'), parts[2].strip('"')
        raise ValueError(f"Invalid FQN: {fqn}")

    def __init__(self):
        self.sf = snowflake_connector

    def _q(self, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return self.sf.execute_query(sql, params)

    def _x(self, sql: str, params: Optional[Dict[str, Any]] = None) -> int:
        return self.sf.execute_non_query(sql, params)

    def ensure_catalog_objects(self) -> None:
        stmts = [
            "create schema if not exists scan_catalog",
            """
            create table if not exists scan_catalog.tables (
              table_catalog text,
              table_schema text,
              table_name text,
              table_type text,
              is_transient boolean,
              is_external boolean,
              is_view boolean,
              row_count number,
              created timestamp_ntz,
              last_altered timestamp_ntz,
              last_commit_time timestamp_ntz,
              refreshed_at timestamp_ntz default current_timestamp(),
              primary key (table_catalog, table_schema, table_name)
            )
            """,
            """
            create table if not exists scan_catalog.columns (
              table_catalog text,
              table_schema text,
              table_name text,
              column_name text,
              data_type text,
              is_nullable text,
              ordinal_position number,
              refreshed_at timestamp_ntz default current_timestamp(),
              primary key (table_catalog, table_schema, table_name, column_name)
            )
            """,
            """
            create table if not exists scan_catalog.table_samples (
              table_catalog text,
              table_schema text,
              table_name text,
              column_name text,
              samples variant,
              sampled_at timestamp_ntz default current_timestamp(),
              primary key (table_catalog, table_schema, table_name, column_name)
            )
            """,
            """
            create table if not exists scan_catalog.column_metrics (
              table_catalog text,
              table_schema text,
              table_name text,
              column_name text,
              data_type text,
              sample_count number,
              sample_nulls number,
              sample_distinct number,
              sample_avg_len number(18,4),
              sample_null_ratio number(10,4),
              sample_uniq_ratio number(10,4),
              sample_avg_entropy number(18,6),
              sample_min_num float,
              sample_max_num float,
              sample_avg_num float,
              sample_stddev_num float,
              refreshed_at timestamp_ntz default current_timestamp(),
              primary key (table_catalog, table_schema, table_name, column_name)
            )
            """,
        ]
        for s in stmts:
            self._x(s)
        # Safeguard: add new columns if table exists without them
        try:
            cols = {r.get('COLUMN_NAME') for r in self._q("select column_name from information_schema.columns where table_schema='SCAN_CATALOG' and table_name='COLUMN_METRICS'")}
            add_cols: List[Tuple[str,str]] = []
            if 'SAMPLE_NULL_RATIO' not in cols:
                add_cols.append(("sample_null_ratio","number(10,4)"))
            if 'SAMPLE_UNIQ_RATIO' not in cols:
                add_cols.append(("sample_uniq_ratio","number(10,4)"))
            if 'SAMPLE_AVG_ENTROPY' not in cols:
                add_cols.append(("sample_avg_entropy","number(18,6)"))
            for name, dtype in add_cols:
                try:
                    self._x(f"alter table scan_catalog.column_metrics add column {name} {dtype}")
                except Exception:
                    pass
        except Exception:
            pass

    def _list_databases(self) -> List[str]:
        rows = self._q("show databases")
        names: List[str] = []
        for r in rows:
            # SHOW DATABASES returns a dict with name under key 'name' or 'name' uppercased depending on driver
            n = r.get("name") or r.get("NAME")
            if n:
                names.append(str(n))
        return names

    def refresh_tables_and_columns(self, include_views: bool = True) -> Tuple[int, int]:
        self.ensure_catalog_objects()
        views_filter = "" if include_views else "where t.table_type in ('BASE TABLE','EXTERNAL TABLE','TRANSIENT')"
        ins_tables = f"""
        merge into scan_catalog.tables tgt using (
          select 
            t.table_catalog,
            t.table_schema,
            t.table_name,
            t.table_type,
            iff(lower(t.is_transient)='true', true, false) as is_transient,
            iff(t.table_type='EXTERNAL TABLE', true, false) as is_external,
            false as is_view,
            t.row_count,
            t.created,
            t.last_altered,
            t.last_commit_time
          from snowflake.account_usage.tables t
          {views_filter}
          union all
          select 
            v.table_catalog,
            v.table_schema,
            v.table_name,
            'VIEW' as table_type,
            false as is_transient,
            false as is_external,
            true as is_view,
            null as row_count,
            v.created,
            v.last_altered,
            null as last_commit_time
          from snowflake.account_usage.views v
          {'' if include_views else ' where 1=0'}
        ) src
        on (tgt.table_catalog=src.table_catalog and tgt.table_schema=src.table_schema and tgt.table_name=src.table_name)
        when matched then update set 
          table_type=src.table_type,
          is_transient=src.is_transient,
          is_external=src.is_external,
          is_view=src.is_view,
          row_count=src.row_count,
          created=src.created,
          last_altered=src.last_altered,
          last_commit_time=src.last_commit_time,
          refreshed_at=current_timestamp()
        when not matched then insert (
          table_catalog, table_schema, table_name, table_type, is_transient, is_external, is_view, row_count, created, last_altered, last_commit_time
        ) values (
          src.table_catalog, src.table_schema, src.table_name, src.table_type, src.is_transient, src.is_external, src.is_view, src.row_count, src.created, src.last_altered, src.last_commit_time
        );
        """
        self._x(ins_tables)
        # ACCOUNT_USAGE columns
        ins_cols = """
        merge into scan_catalog.columns tgt using (
          select 
            c.table_catalog,
            c.table_schema,
            c.table_name,
            c.column_name,
            c.data_type,
            c.is_nullable,
            c.ordinal_position
          from snowflake.account_usage.columns c
          where c.table_catalog is not null and c.table_schema is not null and c.table_name is not null
        ) src
        on (
          tgt.table_catalog=src.table_catalog and tgt.table_schema=src.table_schema and tgt.table_name=src.table_name and tgt.column_name=src.column_name
        )
        when matched then update set 
          data_type=src.data_type,
          is_nullable=src.is_nullable,
          ordinal_position=src.ordinal_position,
          refreshed_at=current_timestamp()
        when not matched then insert (
          table_catalog, table_schema, table_name, column_name, data_type, is_nullable, ordinal_position
        ) values (
          src.table_catalog, src.table_schema, src.table_name, src.column_name, src.data_type, src.is_nullable, src.ordinal_position
        );
        """
        self._x(ins_cols)
        # INFORMATION_SCHEMA fallback for very recent objects per database
        try:
            for db in self._list_databases():
                # Tables and Views from INFORMATION_SCHEMA
                self._x(
                    f"""
                    merge into scan_catalog.tables tgt using (
                      select 
                        t.table_catalog,
                        t.table_schema,
                        t.table_name,
                        t.table_type,
                        iff(lower(t.is_transient)='yes', true, false) as is_transient,
                        iff(t.table_type='EXTERNAL TABLE', true, false) as is_external,
                        iff(t.table_type like '%VIEW%', true, false) as is_view,
                        null as row_count,
                        t.created,
                        t.last_altered,
                        null as last_commit_time
                      from {db}.information_schema.tables t
                    ) src
                    on (tgt.table_catalog=src.table_catalog and tgt.table_schema=src.table_schema and tgt.table_name=src.table_name)
                    when matched then update set 
                      table_type=src.table_type,
                      is_transient=src.is_transient,
                      is_external=src.is_external,
                      is_view=src.is_view,
                      created=src.created,
                      last_altered=src.last_altered,
                      refreshed_at=current_timestamp()
                    when not matched then insert (
                      table_catalog, table_schema, table_name, table_type, is_transient, is_external, is_view, row_count, created, last_altered, last_commit_time
                    ) values (
                      src.table_catalog, src.table_schema, src.table_name, src.table_type, src.is_transient, src.is_external, src.is_view, src.row_count, src.created, src.last_altered, src.last_commit_time
                    );
                    """
                )
                # Columns from INFORMATION_SCHEMA
                self._x(
                    f"""
                    merge into scan_catalog.columns tgt using (
                      select 
                        c.table_catalog,
                        c.table_schema,
                        c.table_name,
                        c.column_name,
                        c.data_type,
                        c.is_nullable,
                        c.ordinal_position
                      from {db}.information_schema.columns c
                    ) src
                    on (
                      tgt.table_catalog=src.table_catalog and tgt.table_schema=src.table_schema and tgt.table_name=src.table_name and tgt.column_name=src.column_name
                    )
                    when matched then update set 
                      data_type=src.data_type,
                      is_nullable=src.is_nullable,
                      ordinal_position=src.ordinal_position,
                      refreshed_at=current_timestamp()
                    when not matched then insert (
                      table_catalog, table_schema, table_name, column_name, data_type, is_nullable, ordinal_position
                    ) values (
                      src.table_catalog, src.table_schema, src.table_name, src.column_name, src.data_type, src.is_nullable, src.ordinal_position
                    );
                    """
                )
        except Exception:
            # If SHOW DATABASES not permitted, skip fallback
            pass
        cnt_tables = self._q("select count(*) as c from scan_catalog.tables")[0]["C"]
        cnt_cols = self._q("select count(*) as c from scan_catalog.columns")[0]["C"]
        return int(cnt_tables), int(cnt_cols)

    def _list_sample_candidates(self, max_tables: int = 50) -> List[Tuple[str, str, str]]:
        q = f"""
        select table_catalog, table_schema, table_name
        from scan_catalog.tables
        where coalesce(row_count,0) > 0 and is_view=false
        order by coalesce(last_altered, created) desc nulls last
        limit {max_tables}
        """
        rows = self._q(q)
        return [(r["TABLE_CATALOG"], r["TABLE_SCHEMA"], r["TABLE_NAME"]) for r in rows]

    def refresh_samples(self, max_tables: int = 20, max_values_per_column: int = 5) -> int:
        self.ensure_catalog_objects()
        todo = self._list_sample_candidates(max_tables=max_tables)
        total_written = 0
        for db, sc, tb in todo:
            fq = f'{db}.{sc}.{tb}'
            cols = self._q(
                f"""
                select column_name from scan_catalog.columns
                where table_catalog=%(db)s and table_schema=%(sc)s and table_name=%(tb)s
                order by ordinal_position
                """,
                {"db": db, "sc": sc, "tb": tb},
            )
            col_names = [r["COLUMN_NAME"] for r in cols]
            if not col_names:
                continue
            select_list = ",".join([f'"{c}"' for c in col_names])
            try:
                samples = self._q(f"select {select_list} from {fq} sample (10 rows) limit {max_values_per_column}")
            except Exception:
                try:
                    samples = self._q(f"select {select_list} from {fq} limit {max_values_per_column}")
                except Exception:
                    samples = []
            per_col: Dict[str, List[Any]] = {c: [] for c in col_names}
            for r in samples:
                for c in col_names:
                    v = r.get(c)
                    if v is not None and len(per_col[c]) < max_values_per_column:
                        per_col[c].append(v)
            for c, vals in per_col.items():
                self._x(
                    """
                    merge into scan_catalog.table_samples tgt using (
                      select %(db)s::text as table_catalog,
                             %(sc)s::text as table_schema,
                             %(tb)s::text as table_name,
                             %(col)s::text as column_name,
                             parse_json(%(samples_json)s) as samples
                    ) src
                    on (
                      tgt.table_catalog=src.table_catalog and tgt.table_schema=src.table_schema and tgt.table_name=src.table_name and tgt.column_name=src.column_name
                    )
                    when matched then update set samples=src.samples, sampled_at=current_timestamp()
                    when not matched then insert (table_catalog, table_schema, table_name, column_name, samples)
                    values (src.table_catalog, src.table_schema, src.table_name, src.column_name, src.samples)
                    """,
                    {
                        "db": db,
                        "sc": sc,
                        "tb": tb,
                        "col": c,
                        "samples_json": json.dumps(vals, default=str),
                    },
                )
                total_written += 1
        return total_written

    def refresh_column_metrics(self, max_tables: int = 20, sample_rows: int = 10000) -> int:
        self.ensure_catalog_objects()
        todo = self._list_sample_candidates(max_tables=max_tables)
        updated = 0
        for db, sc, tb in todo:
            fq = f'{db}.{sc}.{tb}'
            cols = self._q(
                f"""
                select column_name, data_type from scan_catalog.columns
                where table_catalog=%(db)s and table_schema=%(sc)s and table_name=%(tb)s
                order by ordinal_position
                """,
                {"db": db, "sc": sc, "tb": tb},
            ) or []
            for col in cols:
                cname = col.get("COLUMN_NAME")
                dtype = col.get("DATA_TYPE")
                if not cname:
                    continue
                q = (
                    f"select "
                    f"count(*) as sample_count, "
                    f"sum(iff(t.\"{cname}\" is null,1,0)) as sample_nulls, "
                    f"count(distinct t.\"{cname}\") as sample_distinct, "
                    f"avg(len(to_varchar(t.\"{cname}\"))) as sample_avg_len, "
                    f"min(try_to_double(t.\"{cname}\")) as sample_min_num, "
                    f"max(try_to_double(t.\"{cname}\")) as sample_max_num, "
                    f"avg(try_to_double(t.\"{cname}\")) as sample_avg_num, "
                    f"stddev_samp(try_to_double(t.\"{cname}\")) as sample_stddev_num "
                    f"from {fq} as t sample ({int(max(1000, sample_rows))} rows)"
                )
                try:
                    m = (self._q(q) or [{}])[0]
                except Exception:
                    m = {}
                # Compute ratios and entropy from a distribution sample
                try:
                    dist_q = (
                        f"select to_varchar(t.\"{cname}\") as s, count(*) as c "
                        f"from {fq} as t sample ({int(max(1000, sample_rows))} rows) group by 1"
                    )
                    dist_rows = self._q(dist_q) or []
                    total = float(sum([(r.get('C') or 0) for r in dist_rows])) or 0.0
                    entropy = 0.0
                    if total > 0:
                        for r in dist_rows:
                            cval = float(r.get('C') or 0)
                            if cval <= 0:
                                continue
                            p = cval / total
                            entropy += -p * math.log2(p)
                except Exception:
                    entropy = 0.0
                scnt = float(m.get("SAMPLE_COUNT") or 0)
                snull = float(m.get("SAMPLE_NULLS") or 0)
                sdist = float(m.get("SAMPLE_DISTINCT") or 0)
                null_ratio = (snull / scnt) if scnt > 0 else 0.0
                uniq_ratio = (sdist / scnt) if scnt > 0 else 0.0
                self._x(
                    """
                    merge into scan_catalog.column_metrics tgt using (
                      select %(db)s::text as table_catalog,
                             %(sc)s::text as table_schema,
                             %(tb)s::text as table_name,
                             %(col)s::text as column_name,
                             %(dtype)s::text as data_type,
                             %(c)s::number as sample_count,
                             %(n)s::number as sample_nulls,
                             %(d)s::number as sample_distinct,
                             %(al)s::number(18,4) as sample_avg_len,
                             %(nr)s::number(10,4) as sample_null_ratio,
                             %(ur)s::number(10,4) as sample_uniq_ratio,
                             %(en)s::number(18,6) as sample_avg_entropy,
                             %(mi)s::float as sample_min_num,
                             %(ma)s::float as sample_max_num,
                             %(av)s::float as sample_avg_num,
                             %(sd)s::float as sample_stddev_num
                    ) src
                    on (
                      tgt.table_catalog=src.table_catalog and tgt.table_schema=src.table_schema and tgt.table_name=src.table_name and tgt.column_name=src.column_name
                    )
                    when matched then update set 
                      data_type=src.data_type,
                      sample_count=src.sample_count,
                      sample_nulls=src.sample_nulls,
                      sample_distinct=src.sample_distinct,
                      sample_avg_len=src.sample_avg_len,
                      sample_null_ratio=src.sample_null_ratio,
                      sample_uniq_ratio=src.sample_uniq_ratio,
                      sample_avg_entropy=src.sample_avg_entropy,
                      sample_min_num=src.sample_min_num,
                      sample_max_num=src.sample_max_num,
                      sample_avg_num=src.sample_avg_num,
                      sample_stddev_num=src.sample_stddev_num,
                      refreshed_at=current_timestamp()
                    when not matched then insert (
                      table_catalog, table_schema, table_name, column_name, data_type,
                      sample_count, sample_nulls, sample_distinct, sample_avg_len,
                      sample_null_ratio, sample_uniq_ratio, sample_avg_entropy,
                      sample_min_num, sample_max_num, sample_avg_num, sample_stddev_num
                    ) values (
                      src.table_catalog, src.table_schema, src.table_name, src.column_name, src.data_type,
                      src.sample_count, src.sample_nulls, src.sample_distinct, src.sample_avg_len,
                      src.sample_null_ratio, src.sample_uniq_ratio, src.sample_avg_entropy,
                      src.sample_min_num, src.sample_max_num, src.sample_avg_num, src.sample_stddev_num
                    )
                    """,
                    {
                        "db": db,
                        "sc": sc,
                        "tb": tb,
                        "col": cname,
                        "dtype": dtype,
                        "c": m.get("SAMPLE_COUNT"),
                        "n": m.get("SAMPLE_NULLS"),
                        "d": m.get("SAMPLE_DISTINCT"),
                        "al": m.get("SAMPLE_AVG_LEN"),
                        "nr": null_ratio,
                        "ur": uniq_ratio,
                        "en": entropy,
                        "mi": m.get("SAMPLE_MIN_NUM"),
                        "ma": m.get("SAMPLE_MAX_NUM"),
                        "av": m.get("SAMPLE_AVG_NUM"),
                        "sd": m.get("SAMPLE_STDDEV_NUM"),
                    },
                )
                updated += 1
        return updated

    def full_refresh(self, include_views: bool = True, sample_tables: int = 10, sample_values_per_column: int = 5) -> Dict[str, int]:
        t, c = self.refresh_tables_and_columns(include_views=include_views)
        s = self.refresh_samples(max_tables=sample_tables, max_values_per_column=sample_values_per_column)
        m = self.refresh_column_metrics(max_tables=sample_tables, sample_rows=10000)
        return {"tables": t, "columns": c, "samples": s, "metrics": m}

    def list_tables(self, database: Optional[str] = None, limit: int = 500) -> List[str]:
        """List candidate tables (database.schema.table) from the catalog.

        Prefers scan_catalog.tables; falls back to INFORMATION_SCHEMA when needed.
        """
        try:
            self.ensure_catalog_objects()
        except Exception:
            pass
        names: List[str] = []
        try:
            if database:
                rows = self._q(
                    """
                    select table_catalog||'.'||table_schema||'.'||table_name as full_name
                    from scan_catalog.tables
                    where upper(table_catalog)=upper(%(db)s)
                    order by coalesce(refreshed_at, last_altered, created) desc nulls last
                    limit %(lim)s
                    """,
                    {"db": database, "lim": int(max(1, min(10000, limit)))}
                ) or []
            else:
                rows = self._q(
                    """
                    select table_catalog||'.'||table_schema||'.'||table_name as full_name
                    from scan_catalog.tables
                    order by coalesce(refreshed_at, last_altered, created) desc nulls last
                    limit %(lim)s
                    """,
                    {"lim": int(max(1, min(10000, limit)))}
                ) or []
            names = [str(r.get("FULL_NAME") or r.get("full_name")) for r in rows if (r.get("FULL_NAME") or r.get("full_name"))]
        except Exception:
            names = []
        # Fallback to INFORMATION_SCHEMA if empty
        if not names and database:
            try:
                rows = self._q(
                    f"""
                    select "TABLE_CATALOG"||'.'||"TABLE_SCHEMA"||'.'||"TABLE_NAME" as full_name
                    from {database}.information_schema.tables
                    where "TABLE_SCHEMA" not in ('INFORMATION_SCHEMA')
                    order by 1
                    limit {int(max(1, min(10000, limit)))}
                    """
                ) or []
                names = [str(r.get("FULL_NAME") or r.get("full_name")) for r in rows if (r.get("FULL_NAME") or r.get("full_name"))]
            except Exception:
                names = []
        return names

    # --- Sensitive Audit Snapshot (incremental) ---
    def ensure_sensitive_audit_table(self) -> None:
        """Ensure audit table exists using provided best-practice DDL.
        Uses current database and schema-qualified name DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_AUDIT.
        """
        self._x(
            """
            create schema if not exists DATA_CLASSIFICATION_GOVERNANCE;
            create table if not exists DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_AUDIT (
                table_name STRING,
                column_name STRING,
                data_type STRING,
                sensitive_type STRING,
                CIA STRING,
                created_by STRING,
                created_on TIMESTAMP,
                updated_by STRING,
                updated_on TIMESTAMP,
                scan_timestamp TIMESTAMP,
                confidence FLOAT,
                feedback STRING
            )
            """
        )

    def _safe_columns_query(self, database: str, schema: str, table: str) -> List[Dict[str, Any]]:
        """Query INFORMATION_SCHEMA.COLUMNS with best-effort audit fields.
        Falls back when created_by/last_altered_by are unavailable.
        """
        # Attempt with created_by / last_altered_by (may not exist on all accounts)
        try:
            return self._q(
                f"""
                select 
                  c.table_catalog,
                  c.table_schema,
                  c.table_name,
                  c.column_name,
                  c.data_type,
                  c.created_by,
                  c.created_on,
                  c.last_altered_by,
                  c.last_altered
                from {database}.information_schema.columns c
                where c.table_schema = %(sc)s and c.table_name = %(tb)s
                order by c.ordinal_position
                """,
                {"sc": schema, "tb": table},
            )
        except Exception:
            # Fallback without creator/updater names; derive table-level timestamps
            return self._q(
                f"""
                select 
                  c.table_catalog,
                  c.table_schema,
                  c.table_name,
                  c.column_name,
                  c.data_type,
                  cast(null as string) as created_by,
                  t.created as created_on,
                  cast(null as string) as last_altered_by,
                  t.last_altered as last_altered
                from {database}.information_schema.columns c
                join {database}.information_schema.tables t
                  on t.table_catalog = c.table_catalog
                 and t.table_schema = c.table_schema
                 and t.table_name = c.table_name
                where c.table_schema = %(sc)s and c.table_name = %(tb)s
                order by c.ordinal_position
                """,
                {"sc": schema, "tb": table},
            )

    def snapshot_metadata_incremental(
        self,
        full_table_name: str,
    ) -> Dict[str, Any]:
        """Capture an incremental snapshot of column metadata with audit fields into SENSITIVE_AUDIT.

        Args:
            full_table_name: database.schema.table

        Returns:
            Dict with counts: {"scanned": int, "inserted": int, "since": timestamp or None}
        """
        self.ensure_sensitive_audit_table()
        parts = (full_table_name or "").split(".")
        if len(parts) != 3:
            raise ValueError("Table name must be 'database.schema.table'")
        db, sc, tb = parts

        # Determine last scan timestamp from audit table
        try:
            last_row = self._q(
                """
                select max(scan_timestamp) as last_scan
                from DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_AUDIT
                where upper(table_name) = upper(%(t)s)
                """,
                {"t": f"{db}.{sc}.{tb}"},
            ) or []
            last_scan = last_row[0].get("LAST_SCAN") if last_row else None
        except Exception:
            last_scan = None

        rows = self._safe_columns_query(db, sc, tb) or []
        inserted = 0
        for r in rows:
            try:
                created_on = r.get("CREATED_ON") or r.get("CREATED")
                updated_on = r.get("LAST_ALTERED")
                # filter for incremental mode when last_scan exists
                if last_scan and not (
                    (created_on and created_on > last_scan) or (updated_on and updated_on > last_scan)
                ):
                    continue
                self._x(
                    """
                    insert into DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_AUDIT (
                        table_name, column_name, data_type, sensitive_type, CIA,
                        created_by, created_on, updated_by, updated_on, scan_timestamp, confidence, feedback
                    ) values (
                        %(t)s, %(col)s, %(dt)s, %(stype)s, %(cia)s,
                        %(cb)s, %(con)s, %(ub)s, %(uon)s, current_timestamp(), %(conf)s, %(fb)s
                    )
                    """,
                    {
                        "t": f"{db}.{sc}.{tb}",
                        "col": r.get("COLUMN_NAME"),
                        "dt": r.get("DATA_TYPE"),
                        "stype": None,
                        "cia": None,
                        "cb": r.get("CREATED_BY"),
                        "con": created_on,
                        "ub": r.get("LAST_ALTERED_BY"),
                        "uon": updated_on,
                        "conf": None,
                        "fb": None,
                    },
                )
                inserted += 1
            except Exception:
                # best-effort per-row
                pass
        return {"scanned": len(rows), "inserted": inserted, "since": last_scan}

    # --- Embeddings store for column similarity ---
    def ensure_embeddings_objects(self) -> None:
        self._x(
            """
            create schema if not exists scan_catalog;
            create table if not exists scan_catalog.column_embeddings (
              table_catalog text,
              table_schema text,
              table_name text,
              column_name text,
              data_type text,
              name_tokens text,
              embed variant,
              model text,
              updated_at timestamp_ntz default current_timestamp(),
              primary key (table_catalog, table_schema, table_name, column_name)
            )
            """
        )

    def _try_embedder(self):
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            m = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
            return m, 'st:all-MiniLM-L6-v2'
        except Exception:
            return None, 'none'

    def _tokenize(self, s: str) -> List[str]:
        try:
            toks = re.split(r"[^A-Za-z0-9]+", str(s or "").lower())
            return [t for t in toks if t]
        except Exception:
            return []

    def build_column_embeddings(self, max_columns: int = 5000) -> int:
        """Compute/update embeddings for columns from scan_catalog.columns.
        Falls back gracefully if embedding backend is unavailable.
        """
        self.ensure_catalog_objects()
        self.ensure_embeddings_objects()
        rows = self._q(
            f"""
            select table_catalog, table_schema, table_name, column_name, data_type
            from scan_catalog.columns
            order by refreshed_at desc nulls last
            limit {int(max(100, max_columns))}
            """
        ) or []
        embedder, model = self._try_embedder()
        written = 0
        for r in rows:
            try:
                db = r.get('TABLE_CATALOG'); sc = r.get('TABLE_SCHEMA'); tb = r.get('TABLE_NAME'); col = r.get('COLUMN_NAME')
                dt = r.get('DATA_TYPE')
                if not (db and sc and tb and col):
                    continue
                text = f"{sc}.{tb}.{col} {dt}"
                tokens = " ".join(self._tokenize(text))
                vec = None
                if embedder is not None and _np is not None:
                    try:
                        v = embedder.encode([text], normalize_embeddings=True)
                        vec = [float(x) for x in list(v[0])]
                    except Exception:
                        vec = None
                # Fallback: tiny bag-of-words vector of token lengths if embed is None
                if vec is None:
                    toks = self._tokenize(text)
                    vec = [float(len(t)) for t in toks[:32]]
                self._x(
                    """
                    merge into scan_catalog.column_embeddings tgt using (
                      select %(db)s::text as table_catalog,
                             %(sc)s::text as table_schema,
                             %(tb)s::text as table_name,
                             %(col)s::text as column_name,
                             %(dt)s::text as data_type,
                             %(tok)s::text as name_tokens,
                             parse_json(%(emb)s) as embed,
                             %(model)s::text as model
                    ) src
                    on (tgt.table_catalog=src.table_catalog and tgt.table_schema=src.table_schema and tgt.table_name=src.table_name and tgt.column_name=src.column_name)
                    when matched then update set data_type=src.data_type, name_tokens=src.name_tokens, embed=src.embed, model=src.model, updated_at=current_timestamp()
                    when not matched then insert (table_catalog, table_schema, table_name, column_name, data_type, name_tokens, embed, model)
                    values (src.table_catalog, src.table_schema, src.table_name, src.column_name, src.data_type, src.name_tokens, src.embed, src.model)
                    """,
                    {
                        "db": db, "sc": sc, "tb": tb, "col": col,
                        "dt": dt, "tok": tokens, "emb": json.dumps(vec), "model": model,
                    },
                )
                written += 1
            except Exception:
                continue
        return written

    def _cosine(self, a: List[float], b: List[float]) -> float:
        try:
            if not a or not b:
                return 0.0
            if _np is not None:
                va = _np.array(a, dtype=float); vb = _np.array(b, dtype=float)
                denom = (float(_np.linalg.norm(va)) * float(_np.linalg.norm(vb))) + 1e-12
                return float(max(0.0, min(1.0, float(_np.dot(va, vb)) / denom)))
            # naive fallback
            n = min(len(a), len(b))
            num = sum(a[i]*b[i] for i in range(n))
            da = math.sqrt(sum(x*x for x in a[:n]))
            db = math.sqrt(sum(x*x for x in b[:n]))
            return (num / (da*db)) if (da>0 and db>0) else 0.0
        except Exception:
            return 0.0

    def suggest_sensitivity_for_column(self, table_fqn: str, column_name: str, data_type: Optional[str] = None, k: int = 10) -> Dict[str, Any]:
        """Suggest sensitivity for a column via nearest labeled neighbors.
        Pull neighbors from embeddings table joined with latest labels from SENSITIVE_AUDIT.
        """
        self.ensure_embeddings_objects()
        # Build embed for the target column
        embedder, model = self._try_embedder()
        text = f"{table_fqn.split('.')[-2]}.{table_fqn.split('.')[-1]}.{column_name} {data_type or ''}"
        tok = " ".join(self._tokenize(text))
        vec: List[float]
        try:
            if embedder is not None and _np is not None:
                v = embedder.encode([text], normalize_embeddings=True)
                vec = [float(x) for x in list(v[0])]
            else:
                vec = [float(len(t)) for t in (tok.split()[:32])]
        except Exception:
            vec = [float(len(t)) for t in (tok.split()[:32])]

        # Fetch candidate embeddings and their last known labels
        cand = self._q(
            """
            with last_labels as (
              select table_name, column_name, any_value(sensitive_type) as sensitive_type
              from DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_AUDIT
              qualify row_number() over (partition by table_name, column_name order by scan_timestamp desc) = 1
            )
            select e.table_catalog, e.table_schema, e.table_name, e.column_name, e.data_type,
                   e.embed, l.sensitive_type
            from scan_catalog.column_embeddings e
            left join last_labels l
              on upper(l.table_name) = upper(e.table_catalog||'.'||e.table_schema||'.'||e.table_name)
             and upper(l.column_name) = upper(e.column_name)
            limit 2000
            """
        ) or []
        scored: List[Tuple[float, Dict[str, Any]]] = []
        for r in cand:
            try:
                ev = r.get('EMBED')
                if isinstance(ev, str):
                    ev = json.loads(ev)
                sim = self._cosine(vec, list(ev) if isinstance(ev, list) else [])
                scored.append((sim, r))
            except Exception:
                continue
        scored = sorted(scored, key=lambda kv: -kv[0])[:max(1, int(k))]
        votes: Dict[str, float] = {}
        neighbors: List[Dict[str, Any]] = []
        for sim, r in scored:
            lab = r.get('SENSITIVE_TYPE') or None
            if lab:
                votes[lab] = votes.get(lab, 0.0) + float(sim)
            neighbors.append({"neighbor": f"{r.get('TABLE_CATALOG')}.{r.get('TABLE_SCHEMA')}.{r.get('TABLE_NAME')}.{r.get('COLUMN_NAME')}", "sim": round(float(sim),3), "label": lab})
        if votes:
            suggestion = sorted(votes.items(), key=lambda kv: -kv[1])[0][0]
        return {"suggestion": suggestion, "neighbors": neighbors, "model": model}

    def list_bu_mappings(self, limit: int = 1000) -> List[Dict[str, Any]]:
        db = self.sf.execute_query("SELECT CURRENT_DATABASE() AS DB")[0]["DB"]
        sc = "DATA_CLASSIFICATION_GOVERNANCE"
        tb = "BUSINESS_UNIT_MAP"
        try:
            self._x(f"CREATE TABLE IF NOT EXISTS {db}.{sc}.{tb} (FULL_NAME STRING, BUSINESS_UNIT STRING)")
            return self._q(f"SELECT * FROM {db}.{sc}.{tb} ORDER BY FULL_NAME LIMIT {int(limit)}")
        except Exception: return []

    def upsert_bu_mapping(self, full_name: str, business_unit: str) -> None:
        db = self.sf.execute_query("SELECT CURRENT_DATABASE() AS DB")[0]["DB"]
        sc = "DATA_CLASSIFICATION_GOVERNANCE"
        tb = "BUSINESS_UNIT_MAP"
        self._x(f"DELETE FROM {db}.{sc}.{tb} WHERE UPPER(FULL_NAME) = UPPER(%(f)s)", {"f": full_name})
        self._x(f"INSERT INTO {db}.{sc}.{tb} (FULL_NAME, BUSINESS_UNIT) VALUES (%(f)s, %(b)s)", {"f": full_name, "b": business_unit})

    def detect_schema_drift(self, table_fqn: str) -> Dict[str, Any]:
        """Detect added/removed columns vs last audit snapshot and suggest renames via embedding similarity."""
        parts = table_fqn.split('.')
        if len(parts) != 3:
            raise ValueError("table_fqn must be database.schema.table")
        db, sc, tb = parts
        now_cols = self._q(
            """
            select column_name, data_type from scan_catalog.columns
            where table_catalog=%(db)s and table_schema=%(sc)s and table_name=%(tb)s
            order by ordinal_position
            """,
            {"db": db, "sc": sc, "tb": tb},
        ) or []
        last = self._q(
            """
            select distinct column_name
            from DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_AUDIT
            where upper(table_name) = upper(%(t)s)
              and scan_timestamp = (
                select max(scan_timestamp) from DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_AUDIT where upper(table_name)=upper(%(t)s)
              )
            """,
            {"t": f"{db}.{sc}.{tb}"},
        ) or []
        now_set = [str(r.get('COLUMN_NAME')) for r in now_cols]
        last_set = [str(r.get('COLUMN_NAME')) for r in last]
        added = [c for c in now_set if c not in last_set]
        removed = [c for c in last_set if c not in now_set]
        # Heuristic rename: match removed->added by embedding or token similarity
        renames: List[Tuple[str, str, float]] = []
        if added and removed:
            try:
                # precompute embeddings for candidates
                self.ensure_embeddings_objects()
                emb_map: Dict[str, List[float]] = {}
                rows = self._q(
                    """
                    select column_name, embed from scan_catalog.column_embeddings
                    where table_catalog=%(db)s and table_schema=%(sc)s and table_name=%(tb)s
                    """,
                    {"db": db, "sc": sc, "tb": tb},
                ) or []
                for r in rows:
                    ev = r.get('EMBED')
                    if isinstance(ev, str):
                        try: ev = json.loads(ev)
                        except Exception: ev = []
                    emb_map[str(r.get('COLUMN_NAME'))] = list(ev) if isinstance(ev, list) else []
                # simple pairwise best match
                for rm in removed:
                    best = (0.0, None)
                    for ad in added:
                        sim = 0.0
                        v1 = emb_map.get(rm) or []
                        v2 = emb_map.get(ad) or []
                        if v1 and v2:
                            sim = self._cosine(v1, v2)
                        else:
                            # fallback token overlap
                            t1 = set(self._tokenize(rm)); t2 = set(self._tokenize(ad))
                            inter = len(t1 & t2); uni = len(t1 | t2) or 1
                            sim = float(inter) / float(uni)
                        if sim > best[0]:
                            best = (sim, ad)
                    if best[1] is not None and best[0] >= 0.6:
                        renames.append((rm, str(best[1]), round(float(best[0]),3)))
            except Exception:
                pass
        return {"added": added, "removed": removed, "renamed": renames}

metadata_catalog_service = MetadataCatalogService()
asset_catalog_service = metadata_catalog_service
asset_utils = metadata_catalog_service
filter_context = metadata_catalog_service
migration_service = metadata_catalog_service
bu_map_service = metadata_catalog_service
