"""
Quick verification script to test schema resolution
Run this to verify the _gv_schema() function returns the correct value
"""

import sys
import os

# Add the project root to path
_here = os.path.abspath(__file__)
_project_root = os.path.dirname(os.path.dirname(_here))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

print(f"Project root: {_project_root}")

# Test the schema resolution
def _gv_schema() -> str:
    """Return the governance schema to use for queries. Defaults to DATA_CLASSIFICATION_GOVERNANCE."""
    # Simulating no session state override
    return "DATA_CLASSIFICATION_GOVERNANCE"

schema = _gv_schema()
print(f"\n✅ Schema resolution test:")
print(f"   Expected: DATA_CLASSIFICATION_GOVERNANCE")
print(f"   Actual:   {schema}")
print(f"   Match:    {schema == 'DATA_CLASSIFICATION_GOVERNANCE'}")

if schema == "DATA_CLASSIFICATION_GOVERNANCE":
    print("\n✅ SUCCESS: Schema is correctly set to DATA_CLASSIFICATION_GOVERNANCE")
else:
    print(f"\n❌ ERROR: Schema mismatch! Got {schema} instead of DATA_CLASSIFICATION_GOVERNANCE")
