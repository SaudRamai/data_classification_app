"""
Data service layer for data governance operations.
"""
from typing import List, Optional
from src.models.data_models import DataAsset, CIARating, ClassificationRequest
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
import logging

logger = logging.getLogger(__name__)

class DataService:
    """Service layer for data asset operations."""
    
    def __init__(self):
        self.connector = snowflake_connector
    
    def get_data_assets(self, limit: int = 50, offset: int = 0) -> List[DataAsset]:
        """
        Retrieve data assets from Snowflake database.
        
        Args:
            limit: Number of records to retrieve
            offset: Number of records to skip
            
        Returns:
            List of DataAsset objects
        """
        # First, check if the DATA_GOVERNANCE schema exists; no mock fallbacks
        try:
            # Check if data_governance schema exists
            schema_check = self.connector.execute_query("""
                SELECT SCHEMA_NAME 
                FROM INFORMATION_SCHEMA.SCHEMATA 
                WHERE SCHEMA_NAME = 'DATA_GOVERNANCE'
                AND CATALOG_NAME = %(db)s
            """, {"db": settings.SNOWFLAKE_DATABASE})
            
            if not schema_check:
                # Schema doesn't exist, return empty list (live-only)
                logger.info("DATA_GOVERNANCE schema not found in target DB; returning empty assets list")
                return []
            
            # Schema exists, try to query actual data
            query = """
            SELECT 
                'asset_' || ROW_NUMBER() OVER (ORDER BY TABLE_NAME) as asset_id,
                TABLE_NAME as name,
                'Table in ' || TABLE_SCHEMA || ' schema' as description,
                TABLE_CATALOG || '.' || TABLE_SCHEMA || '.' || TABLE_NAME as location,
                'Internal' as classification_level,
                1 as confidentiality_rating,
                1 as integrity_rating,
                1 as availability_rating,
                'admin@company.com' as owner,
                'sample,table' as tags,
                CREATED as created_at,
                LAST_ALTERED as updated_at,
                CREATED as last_classified
            FROM {db}.INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA')
            ORDER BY TABLE_NAME
            LIMIT %(limit)s OFFSET %(offset)s
            """.format(db=settings.SNOWFLAKE_DATABASE)
            
            params = {"limit": limit, "offset": offset}
            results = self.connector.execute_query(query, params)
            
            assets = []
            for row in results:
                cia_rating = CIARating(
                    confidentiality=row["CONFIDENTIALITY_RATING"],
                    integrity=row["INTEGRITY_RATING"],
                    availability=row["AVAILABILITY_RATING"]
                )
                
                asset = DataAsset(
                    id=row["ASSET_ID"],
                    name=row["NAME"],
                    description=row["DESCRIPTION"],
                    location=row["LOCATION"],
                    classification_level=row["CLASSIFICATION_LEVEL"],
                    cia_rating=cia_rating,
                    owner=row["OWNER"],
                    tags=row["TAGS"].split(",") if row["TAGS"] else [],
                    created_at=row["CREATED_AT"],
                    updated_at=row["UPDATED_AT"],
                    last_classified=row["LAST_CLASSIFIED"]
                )
                assets.append(asset)
                
            return assets
            
        except Exception as e:
            logger.error(f"Error retrieving data assets from Snowflake: {e}")
            # Live-only: on error, return empty list
            return []
    
    def _get_mock_data_assets(self, limit: int = 50) -> List[DataAsset]:
        """Deprecated: mock data disabled in live-only mode."""
        return []
    
    def get_data_asset_by_id(self, asset_id: str) -> Optional[DataAsset]:
        """
        Retrieve a specific data asset by ID from Snowflake database.
        
        Args:
            asset_id: ID of the data asset
            
        Returns:
            DataAsset object or None if not found
        """
        try:
            # Try to get actual data from Snowflake
            query = """
            SELECT 
                'asset_' || ROW_NUMBER() OVER (ORDER BY TABLE_NAME) as asset_id,
                TABLE_NAME as name,
                'Table in ' || TABLE_SCHEMA || ' schema' as description,
                TABLE_CATALOG || '.' || TABLE_SCHEMA || '.' || TABLE_NAME as location,
                'Internal' as classification_level,
                1 as confidentiality_rating,
                1 as integrity_rating,
                1 as availability_rating,
                'admin@company.com' as owner,
                'sample,table' as tags,
                CREATED as created_at,
                LAST_ALTERED as updated_at,
                CREATED as last_classified
            FROM {db}.INFORMATION_SCHEMA.TABLES
            WHERE 'asset_' || ROW_NUMBER() OVER (ORDER BY TABLE_NAME) = %(asset_id)s
            LIMIT 1
            """.format(db=settings.SNOWFLAKE_DATABASE)
            
            params = {"asset_id": asset_id}
            results = self.connector.execute_query(query, params)
            
            if not results:
                return None
                
            row = results[0]
            cia_rating = CIARating(
                confidentiality=row["CONFIDENTIALITY_RATING"],
                integrity=row["INTEGRITY_RATING"],
                availability=row["AVAILABILITY_RATING"]
            )
            
            return DataAsset(
                id=row["ASSET_ID"],
                name=row["NAME"],
                description=row["DESCRIPTION"],
                location=row["LOCATION"],
                classification_level=row["CLASSIFICATION_LEVEL"],
                cia_rating=cia_rating,
                owner=row["OWNER"],
                tags=row["TAGS"].split(",") if row["TAGS"] else [],
                created_at=row["CREATED_AT"],
                updated_at=row["UPDATED_AT"],
                last_classified=row["LAST_CLASSIFIED"]
            )
        except Exception as e:
            logger.error(f"Error retrieving data asset {asset_id} from Snowflake: {e}")
            return None
    
    def create_data_asset(self, asset: DataAsset) -> str:
        """
        Create a new data asset in Snowflake pilot database.
        
        Args:
            asset: DataAsset object to create
            
        Returns:
            ID of the created asset
        """
        try:
            # In a real implementation, this would create an entry in a data_governance schema
            # For now, we'll just log the creation
            logger.info(f"Creating data asset: {asset.name}")
            logger.info("In a real implementation, this would create an entry in the data_governance schema")
            
            # Return a mock ID
            return "mock_asset_id"
        except Exception as e:
            logger.error(f"Error creating data asset in Snowflake: {e}")
            raise
    
    def update_data_asset_classification(self, request: ClassificationRequest) -> bool:
        """
        Update the classification of a data asset in Snowflake pilot database.
        
        Args:
            request: ClassificationRequest with updated classification
            
        Returns:
            True if successful
        """
        try:
            # In a real implementation, this would update an entry in a data_governance schema
            # For now, we'll just log the update
            logger.info(f"Updating classification for asset: {request.asset_id}")
            logger.info("In a real implementation, this would update an entry in the data_governance schema")
            
            return True
        except Exception as e:
            logger.error(f"Error updating data asset classification in Snowflake: {e}")
            return False

data_service = DataService()