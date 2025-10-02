"""
Unit tests for authentication service.
"""
import pytest
from unittest.mock import patch
from src.services.auth_service import AuthService
from src.models.data_models import User


class TestAuthService:
    """Test cases for authentication service."""
    
    def test_create_user(self):
        """Test user creation."""
        auth_service = AuthService()
        user = auth_service.create_user(
            username="testuser",
            password="testpassword",
            email="test@example.com",
            role="User"
        )
        
        assert isinstance(user, User)
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == "User"
    
    def test_authenticate_user_success(self):
        """Test successful user authentication."""
        auth_service = AuthService()
        # Create a user first
        auth_service.create_user(
            username="testuser",
            password="testpassword",
            email="test@example.com"
        )
        
        # Authenticate the user
        user = auth_service.authenticate_user("testuser", "testpassword")
        
        assert user is not None
        assert user.username == "testuser"
    
    def test_authenticate_user_failure(self):
        """Test failed user authentication."""
        auth_service = AuthService()
        # Create a user first
        auth_service.create_user(
            username="testuser",
            password="testpassword",
            email="test@example.com"
        )
        
        # Try to authenticate with wrong password
        user = auth_service.authenticate_user("testuser", "wrongpassword")
        
        assert user is None
    
    def test_has_permission(self):
        """Test permission checking."""
        auth_service = AuthService()
        user = User(
            id="user123",
            username="testuser",
            email="test@example.com",
            role="Admin",
            created_at="2023-01-01T00:00:00Z"
        )
        
        # Admin should have all permissions
        assert auth_service.has_permission(user, "read") is True
        assert auth_service.has_permission(user, "write") is True
        assert auth_service.has_permission(user, "delete") is True
        assert auth_service.has_permission(user, "admin") is True
        
        # Test with different role
        user.role = "User"
        assert auth_service.has_permission(user, "read") is True
        assert auth_service.has_permission(user, "write") is False
        assert auth_service.has_permission(user, "delete") is False
        assert auth_service.has_permission(user, "admin") is False