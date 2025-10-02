"""
Unit tests for custom exceptions.
"""
import pytest
from src.utils.exceptions import (
    DataGovernanceError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    DatabaseError,
    ConfigurationError,
    ResourceNotFoundError,
    ConflictError
)


class TestExceptions:
    """Test cases for custom exceptions."""
    
    def test_data_governance_error(self):
        """Test DataGovernanceError base exception."""
        with pytest.raises(DataGovernanceError):
            raise DataGovernanceError("Test error")
    
    def test_authentication_error(self):
        """Test AuthenticationError exception."""
        with pytest.raises(AuthenticationError):
            raise AuthenticationError("Authentication failed")
        
        # Test that it's a subclass of DataGovernanceError
        try:
            raise AuthenticationError("Authentication failed")
        except DataGovernanceError:
            pass  # This should work
        else:
            pytest.fail("AuthenticationError should be a subclass of DataGovernanceError")
    
    def test_validation_error(self):
        """Test ValidationError exception."""
        with pytest.raises(ValidationError):
            raise ValidationError("Validation failed")
    
    def test_database_error(self):
        """Test DatabaseError exception."""
        with pytest.raises(DatabaseError):
            raise DatabaseError("Database operation failed")