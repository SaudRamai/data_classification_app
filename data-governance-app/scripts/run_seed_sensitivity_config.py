import os
import sys
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.connectors.snowflake_connector import snowflake_connector  # type: ignore
from src.services.ai_classification_service import ai_classification_service  # type: ignore


def run_sql_text(sql_text: str) -> None:
    stmts = [s.strip() for s in sql_text.split(";") if s.strip()]
    for stmt in stmts:
        snowflake_connector.execute_non_query(stmt)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=str, default=None)
    parser.add_argument("--file", type=str, default=os.path.join(PROJECT_ROOT, "sql", "011_seed_sensitivity_config.sql"))
    args = parser.parse_args()

    if args.db:
        snowflake_connector.execute_non_query(f"USE DATABASE {args.db}")

    with open(args.file, "r", encoding="utf-8") as f:
        sql_text = f.read()
    run_sql_text(sql_text)

    try:
        ai_classification_service.load_sensitivity_config(force_refresh=True)
    except Exception:
        pass


if __name__ == "__main__":
    main()
