"""
Validation utilities for the data governance application.
"""
import re
from typing import List
from src.config.constants import CLASSIFICATION_LEVELS, CIA_RATINGS


def validate_classification_level(level: str) -> bool:
    """
    Validate that a classification level is valid.
    
    Args:
        level: Classification level to validate
        
    Returns:
        True if valid, False otherwise
    """
    return level in CLASSIFICATION_LEVELS


def validate_cia_rating(rating: int) -> bool:
    """
    Validate that a CIA rating is valid.
    
    Args:
        rating: CIA rating to validate
        
    Returns:
        True if valid, False otherwise
    """
    return rating in CIA_RATINGS


def validate_email(email: str) -> bool:
    """
    Validate that an email address is properly formatted.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_tags(tags: List[str]) -> bool:
    """
    Validate that tags are properly formatted.
    
    Args:
        tags: List of tags to validate
        
    Returns:
        True if valid, False otherwise
    """
    # Check that tags are not empty and don't contain commas
    for tag in tags:
        if not tag or ',' in tag:
            return False
    return True


def validate_snowflake_identifier(identifier: str) -> bool:
    """
    Validate that a Snowflake identifier is properly formatted.
    
    Args:
        identifier: Snowflake identifier to validate
        
    Returns:
        True if valid, False otherwise
    """
    # Basic validation - in a real implementation, this would be more comprehensive
    if not identifier:
        return False
    
    # Check for valid characters (simplified)
    pattern = r'^[a-zA-Z_][a-zA-Z0-9_]*$'
    return re.match(pattern, identifier) is not None