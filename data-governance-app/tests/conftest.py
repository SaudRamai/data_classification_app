"""
pytest configuration and fixtures.
"""
import sys
import os
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest


@pytest.fixture
def sample_cia_rating():
    """Fixture for a sample CIARating object."""
    from src.models.data_models import CIARating
    return CIARating(
        confidentiality=2,
        integrity=2,
        availability=2
    )


@pytest.fixture
def sample_data_asset(sample_cia_rating):
    """Fixture for a sample DataAsset object."""
    from src.models.data_models import DataAsset
    from datetime import datetime
    
    return DataAsset(
        id="test_asset_123",
        name="Test Data Asset",
        description="A sample data asset for testing",
        location="TEST_DB.TEST_SCHEMA.TEST_TABLE",
        classification_level="Internal",
        cia_rating=sample_cia_rating,
        owner="test.user@company.com",
        tags=["test", "sample"],
        created_at=datetime.now(),
        updated_at=datetime.now(),
        last_classified=datetime.now()
    )