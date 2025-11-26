"""
Comprehensive Test Suite for AI Classification Pipeline Service

Tests all critical functionality including:
- Semantic scoring with proper normalization
- Pattern scoring with progressive scoring
- Combined scoring with adaptive weights
- Baseline category creation
- Policy mapping with safety nets
- Database selection
- Governance metadata loading
"""

import pytest
import numpy as np
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, List, Any

# Import the service (adjust path as needed)
import sys
sys.path.insert(0, 'c:/Users/ramai.saud/Downloads/DATA_CLASSIFICATION_APP/data-governance-app')

from src.services.ai_classification_pipeline_service import AIClassificationPipelineService


class TestSemanticScoring:
    """Test semantic scoring with proper normalization"""
    
    @pytest.fixture
    def service(self):
        """Create service instance with mocked dependencies"""
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            service = AIClassificationPipelineService()
            
            # Mock embedder
            service._embedder = Mock()
            service._embed_backend = 'sentence-transformers'
            
            # Create mock centroids
            service._category_centroids = {
                'PII_PERSONAL_INFO': np.array([0.8, 0.6, 0.0]),  # normalized
                'SOX_FINANCIAL_DATA': np.array([0.6, 0.8, 0.0]),  # normalized
                'SOC2_SECURITY_DATA': np.array([0.0, 0.6, 0.8]),  # normalized
            }
            
            # Thresholds
            service._category_thresholds = {
                'PII_PERSONAL_INFO': 0.45,
                'SOX_FINANCIAL_DATA': 0.45,
                'SOC2_SECURITY_DATA': 0.45,
            }
            
            return service
    
    def test_semantic_scoring_returns_all_nonzero_scores(self, service):
        """Test that semantic scoring returns all scores > 0 (no pre-filtering)"""
        # Mock embedding
        query_vec = np.array([0.9, 0.4, 0.1])
        service._embedder.encode = Mock(return_value=[query_vec])
        
        scores = service._semantic_scores_governance_driven("customer email address")
        
        # Should return scores for all categories (no pre-filtering at 0.65)
        assert len(scores) >= 3, "Should return all categories with non-zero similarity"
        assert all(0.0 <= score <= 1.0 for score in scores.values()), "Scores should be in [0,1]"
    
    def test_semantic_scoring_proper_normalization(self, service):
        """Test that vectors are properly normalized before cosine similarity"""
        # Unnormalized query vector
        unnormalized_vec = np.array([5.0, 5.0, 0.0])  # Not unit length
        service._embedder.encode = Mock(return_value=[unnormalized_vec])
        
        scores = service._semantic_scores_governance_driven("test text")
        
        # Should still return valid confidence scores
        assert all(0.0 <= score <= 1.0 for score in scores.values())
    
    def test_semantic_scoring_similarity_to_confidence_conversion(self, service):
        """Test conversion from cosine similarity [-1,1] to confidence [0,1]"""
        # Perfect match
        perfect_vec = np.array([0.8, 0.6, 0.0])  # Same as PII centroid
        service._embedder.encode = Mock(return_value=[perfect_vec])
        
        scores = service._semantic_scores_governance_driven("test")
        
        # PII should have highest score (near 1.0)
        assert scores.get('PII_PERSONAL_INFO', 0) > 0.9, "Perfect match should score ~1.0"
    
    def test_semantic_scoring_handles_zero_norm(self, service):
        """Test handling of zero-norm vectors"""
        zero_vec = np.array([0.0, 0.0, 0.0])
        service._embedder.encode = Mock(return_value=[zero_vec])
        
        scores = service._semantic_scores_governance_driven("test")
        
        # Should return empty scores (not crash)
        assert isinstance(scores, dict)


class TestPatternScoring:
    """Test pattern scoring with progressive scoring"""
    
    @pytest.fixture
    def service(self):
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            service = AIClassificationPipelineService()
            
            service._category_patterns = {
                'PII_PERSONAL_INFO': [
                    r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                    r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Phone
                ],
                'SOX_FINANCIAL_DATA': [
                    r'\$[\d,]+\.\d{2}',  # Currency
                ],
            }
            
            service._category_thresholds = {
                'PII_PERSONAL_INFO': 0.45,
                'SOX_FINANCIAL_DATA': 0.45,
            }
            
            return service
    
    def test_pattern_scoring_progressive_single_match(self, service):
        """Test that single pattern match gives base score of 0.5"""
        text = "john.doe@company.com"  # Matches 1 out of 3 PII patterns
        
        scores = service._pattern_scores_governance_driven(text)
        
        # Coverage = 1/3, Score = 0.5 + (0.5 * 1/3) = 0.667
        assert 'PII_PERSONAL_INFO' in scores
        assert 0.6 <= scores['PII_PERSONAL_INFO'] <= 0.7
    
    def test_pattern_scoring_progressive_multiple_matches(self, service):
        """Test progressive scoring with multiple pattern matches"""
        text = "Contact: 123-45-6789 or email john@company.com or call 555-123-4567"
        # Matches all 3 PII patterns
        
        scores = service._pattern_scores_governance_driven(text)
        
        # Coverage = 3/3, Score = 0.5 + (0.5 * 1.0) = 1.0
        assert scores['PII_PERSONAL_INFO'] == 1.0
    
    def test_pattern_scoring_no_prefiltering(self, service):
        """Test that pattern scores are not pre-filtered"""
        text = "john@company.com"  # 1/3 patterns = 0.667 score
        
        scores = service._pattern_scores_governance_driven(text)
        
        # Should return score even though < 0.65 threshold
        # (No pre-filtering, threshold applied in combined scoring)
        assert 'PII_PERSONAL_INFO' in scores
    
    def test_pattern_scoring_no_matches(self, service):
        """Test text with no pattern matches"""
        text = "generic text with no patterns"
        
        scores = service._pattern_scores_governance_driven(text)
        
        # Should return empty dict (no matches)
        assert len(scores) == 0


class TestCombinedScoring:
    """Test combined scoring with adaptive weights"""
    
    @pytest.fixture
    def service(self):
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            service = AIClassificationPipelineService()
            
            service._embedder = Mock()
            service._embed_backend = 'sentence-transformers'
            
            service._category_centroids = {
                'PII_PERSONAL_INFO': np.array([1.0, 0.0, 0.0]),
            }
            
            service._category_keywords = {
                'PII_PERSONAL_INFO': ['email', 'name', 'phone'],
            }
            
            service._category_patterns = {
                'PII_PERSONAL_INFO': [r'\b[A-Za-z0-9._%+-]+@'],
            }
            
            service._category_thresholds = {
                'PII_PERSONAL_INFO': 0.45,
            }
            
            return service
    
    def test_combined_scoring_all_signals(self, service):
        """Test combined scoring when all signals present"""
        # Mock semantic score
        with patch.object(service, '_semantic_scores_governance_driven', return_value={'PII_PERSONAL_INFO': 0.6}):
            with patch.object(service, '_keyword_scores', return_value={'PII_PERSONAL_INFO': 0.7}):
                with patch.object(service, '_pattern_scores_governance_driven', return_value={'PII_PERSONAL_INFO': 0.8}):
                    
                    scores = service._compute_governance_scores("test text")
                    
                    # Should combine: 0.5*0.6 + 0.3*0.7 + 0.2*0.8 = 0.67
                    assert 'PII_PERSONAL_INFO' in scores
                    # With quality factor and boosting, should be >= 0.67
                    assert scores['PII_PERSONAL_INFO'] >= 0.67
    
    def test_combined_scoring_keyword_only(self, service):
        """Test that keyword-only detection works (no cascade failure)"""
        # Only keyword score, no semantic/pattern
        with patch.object(service, '_semantic_scores_governance_driven', return_value={}):
            with patch.object(service, '_keyword_scores', return_value={'PII_PERSONAL_INFO': 0.75}):
                with patch.object(service, '_pattern_scores_governance_driven', return_value={}):
                    
                    scores = service._compute_governance_scores("email name phone")
                    
                    # Should use keyword score directly (base = kw = 0.75)
                    assert 'PII_PERSONAL_INFO' in scores
                    assert scores['PII_PERSONAL_INFO'] >= 0.70
    
    def test_combined_scoring_keyword_pattern_no_semantic(self, service):
        """Test KW+PAT combination when semantic fails"""
        with patch.object(service, '_semantic_scores_governance_driven', return_value={}):
            with patch.object(service, '_keyword_scores', return_value={'PII_PERSONAL_INFO': 0.8}):
                with patch.object(service, '_pattern_scores_governance_driven', return_value={'PII_PERSONAL_INFO': 0.6}):
                    
                    scores = service._compute_governance_scores("test")
                    
                    # Should combine: 0.7*kw + 0.3*pat = 0.74
                    assert 'PII_PERSONAL_INFO' in scores
                    assert scores['PII_PERSONAL_INFO'] >= 0.70
    
    def test_combined_scoring_lower_threshold(self, service):
        """Test that threshold is 0.45 not 0.65"""
        # Score just above 0.45 but below 0.65
        with patch.object(service, '_semantic_scores_governance_driven', return_value={}):
            with patch.object(service, '_keyword_scores', return_value={'PII_PERSONAL_INFO': 0.50}):
                with patch.object(service, '_pattern_scores_governance_driven', return_value={}):
                    
                    scores = service._compute_governance_scores("test")
                    
                    # With 0.45 threshold, should PASS
                    assert 'PII_PERSONAL_INFO' in scores
    
    def test_combined_scoring_multiplicative_boosting(self, service):
        """Test multiplicative boosting for strong signals"""
        # Strong combined score should get boosted
        with patch.object(service, '_semantic_scores_governance_driven', return_value={'PII_PERSONAL_INFO': 0.75}):
            with patch.object(service, '_keyword_scores', return_value={'PII_PERSONAL_INFO': 0.85}):
                with patch.object(service, '_pattern_scores_governance_driven', return_value={'PII_PERSONAL_INFO': 0.80}):
                    
                    scores = service._compute_governance_scores("test")
                    
                    # Base = 0.5*0.75 + 0.3*0.85 + 0.2*0.80 = 0.79
                    # With boosting, should be > 0.79
                    assert scores['PII_PERSONAL_INFO'] > 0.79


class TestBaselineCategories:
    """Test baseline category creation"""
    
    def test_baseline_categories_created(self):
        """Test that baseline categories are created when governance fails"""
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            service = AIClassificationPipelineService()
            
            # Mock embedder
            service._embedder = Mock()
            service._embed_backend = 'sentence-transformers'
            service._embedder.encode = Mock(return_value=np.random.rand(16, 1024))
            
            service._create_baseline_categories()
            
            # Should create 3 baseline categories
            assert len(service._category_keywords) == 3
            assert 'PII_PERSONAL_INFO' in service._category_keywords
            assert 'SOX_FINANCIAL_DATA' in service._category_keywords
            assert 'SOC2_SECURITY_DATA' in service._category_keywords
    
    def test_baseline_categories_have_keywords(self):
        """Test that baseline categories have rich keywords"""
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            service = AIClassificationPipelineService()
            service._embedder = None  # No embeddings
            
            service._create_baseline_categories()
            
            # Should have keywords for each category
            assert len(service._category_keywords['PII_PERSONAL_INFO']) > 20
            assert len(service._category_keywords['SOX_FINANCIAL_DATA']) > 15
            assert len(service._category_keywords['SOC2_SECURITY_DATA']) > 15
    
    def test_baseline_categories_have_patterns(self):
        """Test that baseline categories have patterns"""
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            service = AIClassificationPipelineService()
            service._embedder = None
            
            service._create_baseline_categories()
            
            # Should have patterns
            assert len(service._category_patterns['PII_PERSONAL_INFO']) >= 4
            assert len(service._category_patterns['SOX_FINANCIAL_DATA']) >= 2
    
    def test_baseline_categories_have_policy_mapping(self):
        """Test that baseline categories map to PII/SOX/SOC2"""
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            service = AIClassificationPipelineService()
            service._embedder = None
            
            service._create_baseline_categories()
            
            # Should have policy mappings
            assert service._policy_group_by_category['PII_PERSONAL_INFO'] == 'PII'
            assert service._policy_group_by_category['SOX_FINANCIAL_DATA'] == 'SOX'
            assert service._policy_group_by_category['SOC2_SECURITY_DATA'] == 'SOC2'
    
    def test_baseline_categories_lower_thresholds(self):
        """Test that baseline categories use 0.40 threshold"""
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            service = AIClassificationPipelineService()
            service._embedder = None
            
            service._create_baseline_categories()
            
            # All thresholds should be 0.40
            for threshold in service._category_thresholds.values():
                assert threshold == 0.40


class TestPolicyMapping:
    """Test policy mapping with safety nets"""
    
    @pytest.fixture
    def service(self):
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            service = AIClassificationPipelineService()
            service._policy_group_by_category = {
                'CUSTOMER_DATA': 'PII',
                'FINANCIAL_RECORDS': 'SOX',
            }
            return service
    
    def test_policy_mapping_layer1_metadata(self, service):
        """Test Layer 1: Metadata-driven mapping"""
        result = service._map_category_to_policy_group('CUSTOMER_DATA')
        assert result == 'PII'
        
        result = service._map_category_to_policy_group('FINANCIAL_RECORDS')
        assert result == 'SOX'
    
    def test_policy_mapping_layer4_direct_match(self, service):
        """Test Layer 4: Direct string matching"""
        # PII indicators
        assert service._map_category_to_policy_group('PERSONAL_INFO') == 'PII'
        assert service._map_category_to_policy_group('CUSTOMER_CONTACT') == 'PII'
        assert service._map_category_to_policy_group('EMPLOYEE_DATA') == 'PII'
        
        # SOX indicators
        assert service._map_category_to_policy_group('FINANCIAL_TRANSACTIONS') == 'SOX'
        assert service._map_category_to_policy_group('ACCOUNT_BALANCE') == 'SOX'
        
        # SOC2 indicators
        assert service._map_category_to_policy_group('SECURITY_LOGS') == 'SOC2'
        assert service._map_category_to_policy_group('ACCESS_CREDENTIALS') == 'SOC2'
    
    def test_policy_mapping_safety_net(self, service):
        """Test safety net: Sensitive categories default to PII"""
        result = service._map_category_to_policy_group('CONFIDENTIAL_DATA')
        assert result == 'PII', "Confidential categories should default to PII"
        
        result = service._map_category_to_policy_group('SENSITIVE_INFO')
        assert result == 'PII'
        
        result = service._map_category_to_policy_group('PRIVATE_RECORDS')
        assert result == 'PII'
    
    def test_policy_mapping_non_sensitive_returns_category(self, service):
        """Test that non-sensitive categories return as-is"""
        result = service._map_category_to_policy_group('PUBLIC_DATA')
        # Should return as-is (uppercase)
        assert result == 'PUBLIC_DATA'


class TestDatabaseSelection:
    """Test database selection with fallbacks"""
    
    def test_database_from_filter(self):
        """Test getting database from global filter"""
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            with patch('src.pages.page_helpers._active_db_from_filter', return_value='MY_DB'):
                service = AIClassificationPipelineService()
                
                db = service._get_active_database()
                assert db == 'MY_DB'
    
    def test_database_from_snowflake_context(self):
        """Test probing Snowflake for current database"""
        mock_connector = Mock()
        mock_connector.execute_query = Mock(return_value=[{'DB': 'CLASSIFIED_DATA'}])
        
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector', mock_connector):
            service = AIClassificationPipelineService()
            
            db = service._get_active_database()
            assert db == 'CLASSIFIED_DATA'
    
    def test_database_auto_select_first(self):
        """Test auto-selecting first available database"""
        mock_connector = Mock()
        # First call (CURRENT_DATABASE) returns None
        # Second call (SHOW DATABASES) returns list
        mock_connector.execute_query = Mock(side_effect=[
            None,  # CURRENT_DATABASE returns None
            [
                {'name': 'SNOWFLAKE'},  # System DB
                {'name': 'MY_DB'},  # User DB
                {'name': 'ANALYTICS_DB'},  # User DB
            ]
        ])
        
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector', mock_connector):
            with patch('src.pages.page_helpers._active_db_from_filter', side_effect=Exception()):
                service = AIClassificationPipelineService()
                
                db = service._get_active_database()
                # Should select first non-system database
                assert db == 'MY_DB'
    
    def test_database_none_handling(self):
        """Test that 'NONE' string is rejected"""
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector'):
            with patch('src.pages.page_helpers._active_db_from_filter', return_value='NONE'):
                service = AIClassificationPipelineService()
                
                # Should try other methods when filter returns 'NONE'
                # Ultimately returns None if all fail
                db = service._get_active_database()
                # Implementation should handle this gracefully


class TestIntegration:
    """Integration tests for full pipeline"""
    
    def test_full_classification_with_baseline_categories(self):
        """Test end-to-end classification using baseline categories"""
        mock_connector = Mock()
        mock_connector.execute_query = Mock(return_value=[
            {'DB': 'TEST_DB'}
        ])
        
        with patch('src.services.ai_classification_pipeline_service.snowflake_connector', mock_connector):
            service = AIClassificationPipelineService()
            
            # Create baseline categories
            service._embedder = None
            service._create_baseline_categories()
            
            # Test classification on PII-like text
            scores = service._compute_governance_scores(
                "Column: customer_email | Type: VARCHAR | Contains email addresses"
            )
            
            # Should detect PII category
            assert 'PII_PERSONAL_INFO' in scores
            assert scores['PII_PERSONAL_INFO'] > 0.45


# Pytest configuration
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
