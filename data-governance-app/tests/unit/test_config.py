"""
Unit tests for configuration.
"""
import os
import pytest
from unittest.mock import patch
from src.config.settings import Settings


class TestConfig:
    """Test cases for configuration."""
    
    @patch.dict(os.environ, {
        "SNOWFLAKE_ACCOUNT": "test_account",
        "SNOWFLAKE_USER": "test_user",
        "SNOWFLAKE_PASSWORD": "test_password",
        "SNOWFLAKE_WAREHOUSE": "test_warehouse",
        "SECRET_KEY": "test_secret_key"
    })
    def test_settings_creation(self):
        """Test settings creation from environment variables."""
        settings = Settings()
        
        assert settings.SNOWFLAKE_ACCOUNT == "test_account"
        assert settings.SNOWFLAKE_USER == "test_user"
        assert settings.SNOWFLAKE_PASSWORD == "test_password"
        assert settings.SNOWFLAKE_WAREHOUSE == "test_warehouse"
        assert settings.SECRET_KEY == "test_secret_key"
        
    @patch.dict(os.environ, {
        "SNOWFLAKE_ACCOUNT": "test_account",
        "SNOWFLAKE_USER": "test_user",
        "SNOWFLAKE_PASSWORD": "test_password",
        "SNOWFLAKE_WAREHOUSE": "test_warehouse",
        "SECRET_KEY": "test_secret_key",
        "APP_NAME": "Test App",
        "DEBUG": "True",
        "LOG_LEVEL": "DEBUG"
    })
    def test_settings_with_optional_values(self):
        """Test settings creation with optional values."""
        settings = Settings()
        
        assert settings.APP_NAME == "Test App"
        assert settings.DEBUG is True
        assert settings.LOG_LEVEL == "DEBUG"