"""
Unit tests for data models.
"""
import pytest
from datetime import datetime
from src.models.data_models import CIARating, DataAsset


class TestDataModels:
    """Test cases for data models."""
    
    def test_cia_rating_creation(self):
        """Test creation of CIARating object."""
        cia_rating = CIARating(
            confidentiality=3,
            integrity=2,
            availability=1
        )
        
        assert cia_rating.confidentiality == 3
        assert cia_rating.integrity == 2
        assert cia_rating.availability == 1
    
    def test_data_asset_creation(self):
        """Test creation of DataAsset object."""
        cia_rating = CIARating(
            confidentiality=3,
            integrity=2,
            availability=1
        )
        
        data_asset = DataAsset(
            id="asset_123",
            name="Test Asset",
            description="A test data asset",
            location="TEST_DB.TEST_SCHEMA.TEST_TABLE",
            classification_level="Confidential",
            cia_rating=cia_rating,
            owner="test.user@company.com",
            tags=["test", "asset"],
            created_at=datetime.now(),
            updated_at=datetime.now(),
            last_classified=datetime.now()
        )
        
        assert data_asset.id == "asset_123"
        assert data_asset.name == "Test Asset"
        assert data_asset.classification_level == "Confidential"
        assert data_asset.cia_rating.confidentiality == 3
        assert "test" in data_asset.tags
    
    def test_data_asset_default_values(self):
        """Test DataAsset creation with default values."""
        cia_rating = CIARating(
            confidentiality=1,
            integrity=1,
            availability=1
        )
        
        data_asset = DataAsset(
            name="Test Asset",
            location="TEST_DB.TEST_SCHEMA.TEST_TABLE",
            classification_level="Internal",
            cia_rating=cia_rating,
            owner="test.user@company.com"
        )
        
        assert data_asset.id is None
        assert data_asset.description is None
        assert data_asset.tags == []