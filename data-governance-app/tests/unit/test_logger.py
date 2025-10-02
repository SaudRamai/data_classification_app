"""
Unit tests for logger utility.
"""
import logging
import pytest
from unittest.mock import patch
from src.utils.logger import setup_logger, AuditLogger


class TestLogger:
    """Test cases for logger utility."""
    
    def test_setup_logger(self):
        """Test logger setup."""
        logger = setup_logger("test_logger")
        assert logger.name == "test_logger"
        # The logger level should be DEBUG because we set DEBUG=True in .env
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) > 0
    
    def test_setup_logger_with_level(self):
        """Test logger setup with specific level."""
        logger = setup_logger("test_logger_debug", "DEBUG")
        assert logger.level == logging.DEBUG
    
    def test_audit_logger(self):
        """Test audit logger functionality."""
        audit_logger = AuditLogger()
        assert audit_logger.logger is not None
        
        # Test that audit methods don't raise exceptions
        audit_logger.log_access("user123", "data_asset_456", "viewed")
        audit_logger.log_classification_change("user123", "asset789", "Internal", "Confidential")
        audit_logger.log_compliance_event("Policy Violation", "Unauthorized access attempt")