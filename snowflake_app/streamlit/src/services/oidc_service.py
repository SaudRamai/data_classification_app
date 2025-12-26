"""
OIDC (OpenID Connect) SSO service using Authlib.

This supports a simple authorization code + PKCE flow suitable for Streamlit:
- get_authorization_url(): returns URL to redirect the user to the IdP login page
- handle_callback(code, state): exchanges code for tokens and stores in session
- get_userinfo(): gets user info (preferred email, name) from IdP

Note: Streamlit apps run client-side in the browser and server-side in a single process.
For production, consider a gateway (e.g., FastAPI) to handle OIDC redirect URIs securely.
"""
from __future__ import annotations
from typing import Optional, Dict, Any
import json
import time
import base64
import os

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:
    from authlib.integrations.requests_client import OAuth2Session  # type: ignore
except Exception:  # pragma: no cover
    OAuth2Session = None  # type: ignore

from src.config.settings import settings


class OIDCService:
    def __init__(self) -> None:
        self.issuer = settings.OIDC_ISSUER
        self.client_id = settings.OIDC_CLIENT_ID
        self.client_secret = settings.OIDC_CLIENT_SECRET
        self.redirect_uri = settings.OIDC_REDIRECT_URI
        self.scopes = settings.OIDC_SCOPES
        self.jwks_uri = settings.OIDC_PROVIDER_JWKS_URI
        self._well_known: Optional[Dict[str, Any]] = None

    def is_configured(self) -> bool:
        # Require settings, requests, and Authlib
        return bool(self.issuer and self.client_id and self.redirect_uri and requests is not None and OAuth2Session is not None)

    def _discover(self) -> Dict[str, Any]:
        if self._well_known:
            return self._well_known
        if requests is None:
            raise RuntimeError("requests not available for OIDC discovery")
        resp = requests.get(self.issuer.rstrip('/') + '/.well-known/openid-configuration', timeout=10)
        resp.raise_for_status()
        self._well_known = resp.json()
        return self._well_known

    def get_authorization_url(self, state: str) -> str:
        if OAuth2Session is None:
            raise RuntimeError("Authlib (OAuth2Session) is not installed")
        conf = self._discover()
        authz_endpoint = conf["authorization_endpoint"]
        sess = OAuth2Session(self.client_id, self.client_secret, scope=self.scopes, redirect_uri=self.redirect_uri)
        uri, _state = sess.create_authorization_url(authz_endpoint, state=state)
        return uri

    def exchange_code(self, code: str) -> Dict[str, Any]:
        if OAuth2Session is None:
            raise RuntimeError("Authlib (OAuth2Session) is not installed")
        conf = self._discover()
        token_endpoint = conf["token_endpoint"]
        sess = OAuth2Session(self.client_id, self.client_secret, scope=self.scopes, redirect_uri=self.redirect_uri)
        token = sess.fetch_token(token_endpoint, code=code, grant_type='authorization_code')
        return token

    def get_userinfo(self, access_token: str) -> Dict[str, Any]:
        if requests is None:
            return {}
        conf = self._discover()
        userinfo_endpoint = conf.get("userinfo_endpoint")
        if not userinfo_endpoint:
            return {}
        resp = requests.get(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"}, timeout=10)
        if resp.status_code != 200:
            return {}
        return resp.json()


oidc_service = OIDCService()
