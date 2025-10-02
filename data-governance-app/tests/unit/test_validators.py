"""
Unit tests for validators utility.
"""
import pytest
from src.utils.validators import (
    validate_classification_level,
    validate_cia_rating,
    validate_email,
    validate_tags,
    validate_snowflake_identifier
)


class TestValidators:
    """Test cases for validators."""
    
    def test_validate_classification_level(self):
        """Test classification level validation."""
        assert validate_classification_level("Public") is True
        assert validate_classification_level("Internal") is True
        assert validate_classification_level("Restricted") is True
        assert validate_classification_level("Confidential") is True
        assert validate_classification_level("Invalid") is False
    
    def test_validate_cia_rating(self):
        """Test CIA rating validation."""
        assert validate_cia_rating(0) is True
        assert validate_cia_rating(1) is True
        assert validate_cia_rating(2) is True
        assert validate_cia_rating(3) is True
        assert validate_cia_rating(4) is False
        assert validate_cia_rating(-1) is False
    
    def test_validate_email(self):
        """Test email validation."""
        assert validate_email("user@company.com") is True
        assert validate_email("user.name@company.com") is True
        assert validate_email("user@company") is False
        assert validate_email("user@.com") is False
        assert validate_email("user@company.") is False
        assert validate_email("usercompany.com") is False
    
    def test_validate_tags(self):
        """Test tag validation."""
        assert validate_tags(["tag1", "tag2"]) is True
        assert validate_tags(["tag1", "tag with spaces"]) is True
        assert validate_tags([""]) is False
        assert validate_tags(["tag,with,commas"]) is False
    
    def test_validate_snowflake_identifier(self):
        """Test Snowflake identifier validation."""
        assert validate_snowflake_identifier("TABLE_NAME") is True
        assert validate_snowflake_identifier("_table_name") is True
        assert validate_snowflake_identifier("TableName123") is True
        assert validate_snowflake_identifier("") is False
        assert validate_snowflake_identifier("123table") is False
        assert validate_snowflake_identifier("table-name") is False