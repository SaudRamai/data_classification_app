#!/usr/bin/env python3
"""
Healthcheck script for Data Governance App
- Verifies Snowflake connectivity
- Runs full discovery scan (batched) to ensure complete DB processing
- Runs basic tests on a sample of discovered assets
Outputs a JSON summary and non-zero exit code if any critical step fails.
"""
import sys
import os
import json
import argparse

# Ensure src/ is importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from src.services.testing_service import testing_service
from src.services.discovery_service import discovery_service
from src.connectors.snowflake_connector import snowflake_connector


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--batch-size', type=int, default=1000)
    parser.add_argument('--max-batches', type=int, default=50)
    parser.add_argument('--test-limit', type=int, default=10, help='Number of assets to run table tests on')
    args = parser.parse_args()

    summary = {
        'connectivity_ok': False,
        'full_scan': {
            'batch_size': args.batch_size,
            'max_batches': args.max_batches,
            'upserted': 0,
        },
        'tests': [],
        'failures': []
    }

    # 1) Connectivity
    summary['connectivity_ok'] = testing_service.connectivity_test()
    if not summary['connectivity_ok']:
        summary['failures'].append('connectivity')

    # 2) Full discovery scan
    try:
        upserted = discovery_service.full_scan(batch_size=args.batch_size, max_batches=args.max_batches)
        summary['full_scan']['upserted'] = upserted
    except Exception as e:
        summary['failures'].append(f'full_scan: {e}')

    # 3) Pick top N assets from inventory and run tests
    try:
        rows = snowflake_connector.execute_query(
            """
            SELECT FULL_NAME
            FROM PILOT_DB.DATA_GOVERNANCE.ASSET_INVENTORY
            ORDER BY ROW_COUNT DESC NULLS LAST, LAST_SEEN DESC
            LIMIT %(lim)s
            """,
            {'lim': args.test_limit},
        )
        for r in rows:
            full = r.get('FULL_NAME')
            res = testing_service.run_table_tests(full)
            summary['tests'].append(res)
            if not res.get('connectivity'):
                summary['failures'].append(f'connectivity:{full}')
            # If any exception captured
            if res.get('error'):
                summary['failures'].append(f"test_error:{full}:{res['error']}")
    except Exception as e:
        summary['failures'].append(f'test_selection: {e}')

    # Output results
    print(json.dumps(summary, indent=2, default=str))

    # Exit code: 0 if no failures, else 1
    sys.exit(0 if not summary['failures'] else 1)


if __name__ == '__main__':
    main()
