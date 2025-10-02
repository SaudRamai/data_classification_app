"""
Logging utility for the data governance application.
"""
import logging
import sys
from typing import Optional
from src.config.settings import settings


def setup_logger(name: str = "data_governance", level: Optional[str] = None) -> logging.Logger:
    """
    Set up and configure logger.
    
    Args:
        name: Name of the logger
        level: Logging level (overrides settings.LOG_LEVEL if provided)
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    log_level = level or settings.LOG_LEVEL
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Prevent adding multiple handlers if logger already exists
    if logger.handlers:
        return logger
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    
    return logger


class AuditLogger:
    """Specialized logger for audit trails."""
    
    def __init__(self):
        self.logger = setup_logger("audit", "INFO")
    
    def log_access(self, user_id: str, resource: str, action: str):
        """Log access to a resource."""
        self.logger.info(f"ACCESS: User {user_id} {action} {resource}")
    
    def log_classification_change(self, user_id: str, asset_id: str, old_level: str, new_level: str):
        """Log classification change."""
        self.logger.info(f"CLASSIFICATION: User {user_id} changed asset {asset_id} from {old_level} to {new_level}")
    
    def log_compliance_event(self, event_type: str, details: str):
        """Log compliance-related event."""
        self.logger.info(f"COMPLIANCE: {event_type} - {details}")


# Create default logger
logger = setup_logger()

# Create audit logger
audit_logger = AuditLogger()