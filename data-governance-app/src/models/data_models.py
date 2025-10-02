"""
Data models for the data governance application.
"""
from typing import Optional, List, Dict
from pydantic import BaseModel
from datetime import datetime

# Classification models
class CIARating(BaseModel):
    """CIA Triad rating model."""
    confidentiality: int  # 0-3
    integrity: int        # 0-3
    availability: int     # 0-3

class DataAsset(BaseModel):
    """Data asset model."""
    id: Optional[str] = None
    name: str
    description: Optional[str] = None
    location: str  # Snowflake table/view name
    classification_level: str  # Public, Internal, Restricted, Confidential
    cia_rating: CIARating
    owner: str
    tags: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_classified: Optional[datetime] = None
    
class ClassificationRequest(BaseModel):
    """Classification request model."""
    asset_id: str
    classification_level: str
    cia_rating: CIARating
    justification: str
    reviewer: Optional[str] = None
    
# Compliance models
class ComplianceControl(BaseModel):
    """Compliance control model."""
    id: str
    name: str
    framework: str  # SOC2, SOX, etc.
    description: str
    implementation_status: str  # Implemented, Partial, Not Implemented
    last_assessed: Optional[datetime] = None
    
# Data quality models
class DataQualityMetric(BaseModel):
    """Data quality metric model."""
    id: Optional[str] = None
    asset_id: str
    dimension: str  # Completeness, Accuracy, etc.
    score: float  # 0.0 - 1.0
    timestamp: datetime
    
# User models
class User(BaseModel):
    """User model."""
    id: str
    username: str
    email: str
    role: str  # Admin, Data Steward, User
    created_at: datetime
    
# Audit models
class AuditLog(BaseModel):
    """Audit log model."""
    id: Optional[str] = None
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    timestamp: datetime
    details: Optional[Dict] = None