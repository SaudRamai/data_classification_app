"""
CLI: Continuous ML Classification Runner

Usage examples:
  python scripts/run_continuous_scan.py --limit 100 --apply-policies
  python scripts/run_continuous_scan.py --limit 50 --no-apply-policies --json

This script runs inside your environment and uses your configured Snowflake
credentials from env/.env (via src.config.settings).
"""
from __future__ import annotations

import os
import sys
import json
import argparse
from datetime import datetime

# Ensure project root on path when invoked from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.services.continuous_classifier_service import continuous_classifier_service


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run continuous data classification and optional enforcement")
    parser.add_argument("--limit", type=int, default=50, help="Max number of tables to scan")
    ap = parser.add_mutually_exclusive_group()
    ap.add_argument("--apply-policies", dest="apply_policies", action="store_true", help="Apply masking policies to detected sensitive columns")
    ap.add_argument("--no-apply-policies", dest="apply_policies", action="store_false", help="Do not apply masking policies")
    parser.set_defaults(apply_policies=False)
    parser.add_argument("--json", dest="as_json", action="store_true", help="Print machine-readable JSON output")

    args = parser.parse_args(argv)

    try:
        res = continuous_classifier_service.run_scan(limit=int(args.limit), apply_policies=bool(args.apply_policies))
        if args.as_json:
            print(json.dumps({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "result": res,
            }, default=str))
        else:
            dist = res.get('classification_distribution', {})
            print("=== Continuous Classification Summary ===")
            print(f"Scanned tables: {res.get('count_tables', 0)}")
            print(f"Sensitive columns detected: {res.get('sensitive_columns', 0)}")
            print(f"Policies applied: {res.get('policies_applied', 0)}")
            print("Classification distribution:")
            for k, v in dist.items():
                print(f"  - {k}: {v}")
            # Show top 10 results compactly
            print("Top results:")
            for r in (res.get('results', [])[:10]):
                table = r.get('table')
                label = r.get('classification')
                conf = r.get('confidence')
                pol = r.get('policies_applied')
                print(f"  {table}: {label}, conf={conf}, policies={pol}")
        return 0
    except Exception as e:
        if args.as_json:
            print(json.dumps({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "error": str(e),
            }))
        else:
            print(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
