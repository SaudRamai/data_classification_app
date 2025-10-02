"""
Authentication service for the data governance application.
"""
from typing import Optional
from src.models.data_models import User
import hashlib
import secrets
import logging

logger = logging.getLogger(__name__)

class AuthService:
    """Service for handling authentication and authorization."""
    
    def __init__(self):
        # In a real implementation, this would connect to a user database
        self.users = {}
        
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: User's username
            password: User's password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        # In a real implementation, we would hash the password and check against a database
        # This is a simplified example for demonstration
        if username in self.users:
            user_data = self.users[username]
            salt = user_data["salt"]
            stored_hash = user_data["password_hash"]
            
            # Hash the provided password with the stored salt
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            
            if password_hash == stored_hash:
                return User(
                    id=user_data["id"],
                    username=username,
                    email=user_data["email"],
                    role=user_data["role"],
                    created_at=user_data["created_at"]
                )
                
        logger.warning(f"Authentication failed for user: {username}")
        return None
    
    def create_user(self, username: str, password: str, email: str, role: str = "User") -> User:
        """
        Create a new user.
        
        Args:
            username: User's username
            password: User's password
            email: User's email
            role: User's role
            
        Returns:
            Created User object
        """
        # Generate a salt and hash the password
        salt = secrets.token_bytes(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        
        # Create user data
        user_data = {
            "id": f"user_{len(self.users) + 1}",
            "username": username,
            "email": email,
            "role": role,
            "password_hash": password_hash,
            "salt": salt,
            "created_at": "2023-01-01T00:00:00Z"  # Simplified for example
        }
        
        self.users[username] = user_data
        
        user = User(
            id=user_data["id"],
            username=username,
            email=email,
            role=role,
            created_at=user_data["created_at"]
        )
        
        logger.info(f"Created new user: {username}")
        return user
    
    def has_permission(self, user: User, permission: str) -> bool:
        """
        Check if a user has a specific permission.
        
        Args:
            user: User object
            permission: Permission to check
            
        Returns:
            True if user has permission, False otherwise
        """
        # Simplified permission checking
        # In a real implementation, this would check against a permissions matrix
        permissions_by_role = {
            "Admin": ["read", "write", "delete", "admin"],
            "Data Steward": ["read", "write"],
            "User": ["read"]
        }
        
        return permission in permissions_by_role.get(user.role, [])

auth_service = AuthService()