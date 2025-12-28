"""
Services layer for the Data Governance Application.
Consolidated entry points for core application logic.
"""
try:
    from .asset_catalog_service import asset_catalog_service
except Exception:
    asset_catalog_service = None  # type: ignore
from .authorization_service import authz as authorization_service
from .classification_audit_service import classification_audit_service as audit_service
from .classification_pipeline_service import ai_classification_pipeline_service as ai_pipeline_service
from .classification_workflow_service import classification_workflow_service
from .compliance_service import compliance_service
from .governance_config_service import governance_config_service
from .notifier_service import notify_slack, notify_email
from .tagging_service import tagging_service, label_service
from .asset_catalog_service import bu_map_service, migration_service
from .oidc_service import oidc_service

__all__ = [
    "asset_catalog_service",
    "authorization_service",
    "audit_service",
    "ai_pipeline_service",
    "classification_workflow_service",
    "compliance_service",
    "governance_config_service",
    "notify_slack",
    "notify_email",
    "tagging_service",
    "label_service",
    "bu_map_service",
    "migration_service",
    "oidc_service",
]
