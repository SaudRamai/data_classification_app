"""
Data models for the data governance application.
"""
from typing import Optional, List, Dict
from pydantic import BaseModel
from datetime import datetime

# Classification models

    
    
# Compliance models
    
# Data quality models
    
# User models
class User(BaseModel):
    """User model."""
    id: str
    username: str
    email: str
    role: str  # Admin, Data Steward, User
    created_at: datetime
    
# Audit models
