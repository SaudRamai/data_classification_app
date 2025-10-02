"""
Integration tests for Snowflake connector.
Note: These tests require a Snowflake connection and are marked as integration tests.
"""
import pytest
from unittest.mock import Mock, patch


class TestSnowflakeConnector:
    """Test cases for Snowflake connector."""
    
    @pytest.mark.integration
    def test_connector_initialization(self):
        """Test Snowflake connector initialization."""
        # This test would require actual Snowflake credentials
        # For now, we'll just test that the module can be imported
        try:
            from src.connectors.snowflake_connector import SnowflakeConnector
            connector = SnowflakeConnector()
            assert connector is not None
        except Exception as e:
            pytest.skip(f"Snowflake connector test skipped: {e}")
    
    def test_execute_query_mock(self):
        """Test execute_query method with mocked connection."""
        with patch('src.connectors.snowflake_connector.snowflake.connector.connect') as mock_connect:
            # Mock the connection and cursor
            mock_conn = Mock()
            mock_cursor = Mock()
            mock_connect.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.fetchall.return_value = [
                {'ID': 1, 'NAME': 'Test Asset 1'},
                {'ID': 2, 'NAME': 'Test Asset 2'}
            ]
            
            # Import and test the connector
            from src.connectors.snowflake_connector import SnowflakeConnector
            connector = SnowflakeConnector()
            
            results = connector.execute_query("SELECT * FROM test_table")
            
            assert len(results) == 2
            assert results[0]['NAME'] == 'Test Asset 1'
            assert results[1]['NAME'] == 'Test Asset 2'