"""
Unit tests for data service.
"""
import pytest
from unittest.mock import Mock, patch
from datetime import datetime
from src.services.data_service import DataService
from src.models.data_models import DataAsset, CIARating, ClassificationRequest


class TestDataService:
    """Test cases for data service."""
    
    def test_get_data_assets(self):
        """Test get_data_assets method."""
        # Mock the connector
        mock_connector = Mock()
        mock_connector.execute_query.return_value = [
            {
                'ASSET_ID': 'asset_123',
                'NAME': 'Test Asset',
                'DESCRIPTION': 'A test asset',
                'LOCATION': 'TEST_DB.TEST_SCHEMA.TEST_TABLE',
                'CLASSIFICATION_LEVEL': 'Internal',
                'CONFIDENTIALITY_RATING': 1,
                'INTEGRITY_RATING': 1,
                'AVAILABILITY_RATING': 1,
                'OWNER': 'test.user@company.com',
                'TAGS': 'test,asset',
                'CREATED_AT': datetime.now(),
                'UPDATED_AT': datetime.now(),
                'LAST_CLASSIFIED': datetime.now()
            }
        ]
        
        # Patch the snowflake_connector instance
        with patch('src.services.data_service.snowflake_connector', mock_connector):
            service = DataService()
            assets = service.get_data_assets(limit=10, offset=0)
            
            # Verify the query was executed with correct parameters
            mock_connector.execute_query.assert_called_once()
            assert len(assets) == 1
            assert isinstance(assets[0], DataAsset)
            assert assets[0].id == 'asset_123'
            assert assets[0].name == 'Test Asset'
    
    def test_get_data_asset_by_id(self):
        """Test get_data_asset_by_id method."""
        # Mock the connector
        mock_connector = Mock()
        mock_connector.execute_query.return_value = [
            {
                'ASSET_ID': 'asset_123',
                'NAME': 'Test Asset',
                'DESCRIPTION': 'A test asset',
                'LOCATION': 'TEST_DB.TEST_SCHEMA.TEST_TABLE',
                'CLASSIFICATION_LEVEL': 'Internal',
                'CONFIDENTIALITY_RATING': 1,
                'INTEGRITY_RATING': 1,
                'AVAILABILITY_RATING': 1,
                'OWNER': 'test.user@company.com',
                'TAGS': 'test,asset',
                'CREATED_AT': datetime.now(),
                'UPDATED_AT': datetime.now(),
                'LAST_CLASSIFIED': datetime.now()
            }
        ]
        
        # Patch the snowflake_connector instance
        with patch('src.services.data_service.snowflake_connector', mock_connector):
            service = DataService()
            asset = service.get_data_asset_by_id('asset_123')
            
            # Verify the query was executed with correct parameters
            mock_connector.execute_query.assert_called_once()
            assert asset is not None
            assert isinstance(asset, DataAsset)
            assert asset.id == 'asset_123'
            assert asset.name == 'Test Asset'
    
    def test_create_data_asset(self):
        """Test create_data_asset method."""
        # Mock the connector
        mock_connector = Mock()
        mock_connector.execute_non_query.return_value = 1
        
        # Create a test data asset
        cia_rating = CIARating(
            confidentiality=1,
            integrity=1,
            availability=1
        )
        data_asset = DataAsset(
            name="New Test Asset",
            description="A new test asset",
            location="TEST_DB.TEST_SCHEMA.NEW_TABLE",
            classification_level="Internal",
            cia_rating=cia_rating,
            owner="test.user@company.com",
            tags=["new", "test"]
        )
        
        # Patch the snowflake_connector instance
        with patch('src.services.data_service.snowflake_connector', mock_connector):
            service = DataService()
            asset_id = service.create_data_asset(data_asset)
            
            # Verify the query was executed
            mock_connector.execute_non_query.assert_called_once()
            assert asset_id == "generated_id"
    
    def test_update_data_asset_classification(self):
        """Test update_data_asset_classification method."""
        # Mock the connector
        mock_connector = Mock()
        mock_connector.execute_non_query.return_value = 1
        
        # Create a test classification request
        cia_rating = CIARating(
            confidentiality=2,
            integrity=2,
            availability=2
        )
        classification_request = ClassificationRequest(
            asset_id="asset_123",
            classification_level="Confidential",
            cia_rating=cia_rating,
            justification="Contains sensitive information"
        )
        
        # Patch the snowflake_connector instance
        with patch('src.services.data_service.snowflake_connector', mock_connector):
            service = DataService()
            result = service.update_data_asset_classification(classification_request)
            
            # Verify the query was executed
            mock_connector.execute_non_query.assert_called_once()
            assert result is True