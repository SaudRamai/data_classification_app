"""
Test script to verify upsert_sensitive_keyword method is working

Run this to test if the upsert method can save to the database
"""

import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from services.ai_classification_pipeline_service import AIClassificationPipelineService
import logging

# Set up logging to see the detailed messages
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s'
)

logger = logging.getLogger(__name__)

def test_upsert():
    """Test the upsert method"""
    
    logger.info("=" * 80)
    logger.info("TESTING UPSERT METHOD")
    logger.info("=" * 80)
    
    try:
        # Initialize the service
        logger.info("Initializing AIClassificationPipelineService...")
        service = AIClassificationPipelineService()
        
        # Test 1: Upsert SOCIAL_SECURITY_NUMBER to PII
        logger.info("\n" + "=" * 80)
        logger.info("TEST 1: Upserting 'SOCIAL_SECURITY_NUMBER' to 'PII'")
        logger.info("=" * 80)
        
        result = service.upsert_sensitive_keyword(
            keyword="SOCIAL_SECURITY_NUMBER",
            category_name="PII",
            match_type="CONTAINS",
            sensitivity_weight=10.0
        )
        
        if result:
            logger.info("✅ TEST 1 PASSED: Upsert returned True")
        else:
            logger.error("❌ TEST 1 FAILED: Upsert returned False")
        
        # Test 2: Upsert EMAIL_ADDRESS to PII
        logger.info("\n" + "=" * 80)
        logger.info("TEST 2: Upserting 'EMAIL_ADDRESS' to 'PII'")
        logger.info("=" * 80)
        
        result = service.upsert_sensitive_keyword(
            keyword="EMAIL_ADDRESS",
            category_name="PII",
            match_type="CONTAINS",
            sensitivity_weight=8.0
        )
        
        if result:
            logger.info("✅ TEST 2 PASSED: Upsert returned True")
        else:
            logger.error("❌ TEST 2 FAILED: Upsert returned False")
        
        logger.info("\n" + "=" * 80)
        logger.info("TESTS COMPLETE")
        logger.info("=" * 80)
        logger.info("\nNow verify in database:")
        logger.info("SELECT * FROM SENSITIVE_KEYWORDS WHERE KEYWORD_STRING IN ('SOCIAL_SECURITY_NUMBER', 'EMAIL_ADDRESS');")
        
    except Exception as e:
        logger.error(f"❌ TEST FAILED with exception: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    test_upsert()
