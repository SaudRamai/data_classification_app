"""
Custom exception classes for the data governance application.
"""

class DataGovernanceError(Exception):
    """Base exception class for data governance application errors."""
    pass


class AuthenticationError(DataGovernanceError):
    """Raised when authentication fails."""
    pass


class AuthorizationError(DataGovernanceError):
    """Raised when user is not authorized to perform an action."""
    pass


class ValidationError(DataGovernanceError):
    """Raised when data validation fails."""
    pass


class DatabaseError(DataGovernanceError):
    """Raised when database operations fail."""
    pass


class ConfigurationError(DataGovernanceError):
    """Raised when configuration is invalid or missing."""
    pass


class ResourceNotFoundError(DataGovernanceError):
    """Raised when a requested resource is not found."""
    pass


class ConflictError(DataGovernanceError):
    """Raised when there is a conflict with the current state."""
    pass