
import pytest
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fix_governance_data import fix_governance_data

def test_apply_governance_fix():
    """
    Test wrapper to execute the governance data fix.
    """
    print("\nRunning governance data fix from pytest...")
    fix_governance_data()
    print("\nGovernance data fix completed.")
    assert True
