"""
Notifier Service (Lightweight Utility)
Sends alerts for compliance and SLA violations via Slack or Email.
"""
from __future__ import annotations
import os
import json
import logging
from typing import Optional

try:
    import requests
except ImportError:
    requests = None

try:
    import smtplib
    from email.mime.text import MIMEText
except ImportError:
    smtplib = None
    MIMEText = None

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

def _send_slack(target_url: str, subject: str, message: str) -> bool:
    if not requests:
        logger.warning("Requests not installed, cannot send Slack notification")
        return False
    
    payload = {"text": f"*{subject}*\n{message}"}
    try:
        resp = requests.post(
            target_url, 
            data=json.dumps(payload), 
            headers={"Content-Type": "application/json"}, 
            timeout=10
        )
        return resp.status_code == 200
    except Exception as e:
        logger.error(f"Failed to send Slack notification: {e}")
        return False

def _send_email(to_email: str, subject: str, message: str) -> bool:
    if not smtplib or not MIMEText:
        logger.warning("smtplib or MIMEText not available, cannot send email")
        return False
    
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587") or 587)
    smtp_from = os.getenv("SMTP_FROM", "no-reply@datagov.local").strip()

    if not all([smtp_host, smtp_user, smtp_pass]):
        logger.warning("SMTP not fully configured, skipping email")
        return False

    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = to_email
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [to_email], msg.as_string())
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

def notify_slack(subject: str, message: str, target_url: Optional[str] = None) -> bool:
    """Public wrapper to send a Slack notification.
    Uses SLACK_WEBHOOK_URL env var if target_url is not provided.
    Returns True on success, False otherwise.
    """
    url = (target_url or os.getenv("SLACK_WEBHOOK_URL", "").strip())
    if not url:
        logger.warning("No Slack webhook URL configured; skipping Slack notification")
        return False
    return _send_slack(url, subject, message)

def notify_email(to_email: str, subject: str, message: str) -> bool:
    """Public wrapper to send an email notification.
    Returns True on success, False otherwise.
    """
    return _send_email(to_email, subject, message)

def notify_owner(asset_full_name: str, subject: str, message: str, owner_email: Optional[str] = None) -> bool:
    """
    Unified entry point for notifying an asset owner.
    """
    logger.info(f"Notifying owner of {asset_full_name}: {subject}")
    
    # Try Slack if webhook is configured
    slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if slack_webhook:
        _send_slack(slack_webhook, f"{subject} - {asset_full_name}", message)
    
    # Try Email if we have an owner email
    if owner_email:
        _send_email(owner_email, subject, f"Asset: {asset_full_name}\n\n{message}")
    
    return True

# Backward compatibility singleton wrapper if needed
class NotifierWrapper:
    def notify_owner(self, *args, **kwargs):
        return notify_owner(*args, **kwargs)

notifier_service = NotifierWrapper()
