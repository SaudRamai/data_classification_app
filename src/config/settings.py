"""
Application configuration settings.

Security note:
- Do NOT load secrets from a checked-in .env file. This app expects secrets to be provided
  securely via environment variables or a secrets manager (e.g., Azure Key Vault, AWS Secrets
  Manager, HashiCorp Vault, Snowflake External Secrets). Ensure CI/CD or your runtime environment
  injects these values at startup.
"""
import os
import logging
import secrets
from typing import Optional
from pydantic import BaseModel

try:
    from pydantic import ConfigDict
except ImportError:
    ConfigDict = None

try:
    import streamlit as st  # optional; used to read local secrets during dev
except Exception:  # pragma: no cover
    st = None


class Settings(BaseModel):
    # Do not load from local .env; rely strictly on process environment / secrets manager.
    if ConfigDict:
        model_config = ConfigDict(case_sensitive=True)
    else:
        class Config:
            case_sensitive = True

    # Snowflake connection settings (optional for local dev; enforced at connection time)
    SNOWFLAKE_ACCOUNT: Optional[str] = None
    SNOWFLAKE_USER: Optional[str] = None
    SNOWFLAKE_PASSWORD: Optional[str] = None
    SNOWFLAKE_WAREHOUSE: Optional[str] = None
    SNOWFLAKE_DATABASE: Optional[str] = None
    SNOWFLAKE_SCHEMA: Optional[str] = None
    
    # Application settings
    APP_NAME: str = "Data Governance Application"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    
    # Security settings
    SECRET_KEY: Optional[str] = None
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # OIDC / SSO settings (optional)
    OIDC_ISSUER: Optional[str] = None  # e.g., https://login.microsoftonline.com/<tenant>/v2.0
    OIDC_CLIENT_ID: Optional[str] = None
    OIDC_CLIENT_SECRET: Optional[str] = None
    OIDC_REDIRECT_URI: Optional[str] = None  # e.g., http://localhost:8501
    OIDC_SCOPES: str = "openid profile email"
    OIDC_PROVIDER_JWKS_URI: Optional[str] = None  # optional override; otherwise discovered from issuer
    
    # SLA / Monitoring thresholds (can be overridden via environment)
    SLA_UNCLASSIFIED_BD_THRESHOLD: int = 5           # business days to classify new assets
    SLA_REVIEW_QTR_DAYS: int = 90                    # days considered for quarterly review completion
    SLA_REVIEW_ANNUAL_DAYS: int = 365                # days considered for annual readiness
    SLA_AUDIT_PENALTY_PER_VIOLATION: float = 0.5     # points to subtract per open violation
    SLA_AUDIT_PENALTY_MAX: float = 10.0              # max penalty points
    SLA_PROVISIONAL_IA_DAYS: int = 7                 # grace period (days) to finalize provisional I/A

    def __init__(self, **data):
        # Manual environment variable loading to replace pydantic-settings
        # Compatible with both Pydantic V1 and V2
        fields = []
        if hasattr(self, 'model_fields'):  # V2
            fields = self.model_fields.keys()
        elif hasattr(self, '__fields__'):  # V1
            fields = self.__fields__.keys()
            
        env_values = {}
        for f in fields:
            val = os.environ.get(f)
            if val is not None:
                env_values[f] = val
        
        # Merge env values with passed data (data takes precedence)
        super().__init__(**{**env_values, **data})
    
def _populate_env_from_streamlit_secrets():
    """Populate os.environ from Streamlit secrets if available.

    This is intended for local development only. In production, prefer environment
    variables or an external secrets manager. Existing env vars are never overridden.
    """
    if st is None:
        return
    try:
        sec = getattr(st, "secrets", None)
        if not sec:
            return
        # flat keys expected by the app
        for key in (
            "SNOWFLAKE_ACCOUNT",
            "SNOWFLAKE_USER",
            "SNOWFLAKE_PASSWORD",
            "SNOWFLAKE_WAREHOUSE",
            "SNOWFLAKE_DATABASE",
            "SNOWFLAKE_SCHEMA",
            "SECRET_KEY",
        ):
            if key not in os.environ and key in sec:
                val = sec.get(key)
                if val is not None:
                    os.environ[key] = str(val)
    except Exception:
        # best-effort only; never fail settings initialization due to secrets read
        pass

# Best-effort: load from Streamlit secrets for local dev before instantiation
_populate_env_from_streamlit_secrets()

def _ensure_dev_defaults():
    """Ensure minimal defaults for local development only.

    - SECRET_KEY: auto-generate if missing, so the app can start.
    """
    try:
        if not os.environ.get("SECRET_KEY"):
            # Generate a stable-ish secret only for the current run
            os.environ["SECRET_KEY"] = secrets.token_urlsafe(32)
            logging.getLogger(__name__).warning(
                "SECRET_KEY not provided; generated a temporary key for this session (dev only)."
            )
    except Exception:
        pass

_ensure_dev_defaults()

# Create settings instance
settings = Settings()

# Post-initialization cleanup for environment-injected 'NONE' values
for key in (
    "SNOWFLAKE_ACCOUNT",
    "SNOWFLAKE_USER",
    "SNOWFLAKE_PASSWORD",
    "SNOWFLAKE_WAREHOUSE",
    "SNOWFLAKE_DATABASE",
    "SNOWFLAKE_SCHEMA",
):
    val = getattr(settings, key, None)
    if val and str(val).strip().upper() in ("NONE", "NULL", "(NONE)", "UNKNOWN", ""):
        setattr(settings, key, None)
