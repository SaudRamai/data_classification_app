"""
Notifier service: sends alerts for compliance and SLA violations.
- Primary channel: Slack via webhook (SLACK_WEBHOOK_URL)
- Optional fallback: SMTP email (SMTP_* environment variables)
- Reads from DATA_GOVERNANCE.NOTIFICATIONS_OUTBOX and marks as sent.

No secrets are stored in code. All credentials must come from environment or a secrets manager.
"""
from __future__ import annotations
import os
import json
import time
from typing import List, Dict, Any

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:
    import smtplib
    from email.mime.text import MIMEText
except Exception:  # pragma: no cover
    smtplib = None  # type: ignore
    MIMEText = None  # type: ignore

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

DB = settings.SNOWFLAKE_DATABASE


class NotifierService:
    def __init__(self) -> None:
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "").strip()
        self.smtp_host = os.getenv("SMTP_HOST", "").strip()
        self.smtp_user = os.getenv("SMTP_USER", "").strip()
        self.smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
        self.smtp_port = int(os.getenv("SMTP_PORT", "587") or 587)
        self.smtp_from = os.getenv("SMTP_FROM", "no-reply@datagov.local").strip()

    def _ensure_tables(self) -> None:
        snowflake_connector.execute_non_query(
            f"""
            CREATE SCHEMA IF NOT EXISTS {DB}.DATA_GOVERNANCE;
            CREATE TABLE IF NOT EXISTS {DB}.DATA_GOVERNANCE.NOTIFICATIONS_OUTBOX (
              ID STRING,
              CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP,
              CHANNEL STRING,            -- 'SLACK' or 'EMAIL'
              TARGET STRING,             -- webhook URL or email address
              SUBJECT STRING,
              BODY STRING,
              SENT_AT TIMESTAMP_NTZ,
              SENT_RESULT STRING
            );
            """
        )

    def _send_slack(self, target_url: str, subject: str, body: str) -> str:
        if not requests:
            return "requests_not_installed"
        payload = {"text": f"*{subject}*\n{body}"}
        try:
            resp = requests.post(target_url, data=json.dumps(payload), headers={"Content-Type": "application/json"}, timeout=10)
            return f"{resp.status_code}"
        except Exception as e:  # pragma: no cover
            return f"error:{e}"

    def _send_email(self, to_email: str, subject: str, body: str) -> str:
        if not (smtplib and MIMEText):
            return "smtplib_not_available"
        if not (self.smtp_host and self.smtp_user and self.smtp_password):
            return "smtp_not_configured"
        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.smtp_from
            msg["To"] = to_email
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.smtp_from, [to_email], msg.as_string())
            return "sent"
        except Exception as e:  # pragma: no cover
            return f"error:{e}"

    def run_once(self, limit: int = 100) -> int:
        """Send up to <limit> unsent notifications and mark them SENT_AT.
        Returns number of notifications processed.
        """
        self._ensure_tables()
        rows = snowflake_connector.execute_query(
            f"""
            SELECT ID, CHANNEL, TARGET, SUBJECT, BODY
            FROM {DB}.DATA_GOVERNANCE.NOTIFICATIONS_OUTBOX
            WHERE SENT_AT IS NULL
            ORDER BY CREATED_AT
            LIMIT %(lim)s
            """,
            {"lim": int(limit)}
        ) or []
        count = 0
        for r in rows:
            nid = r.get("ID")
            channel = (r.get("CHANNEL") or "").upper()
            target = r.get("TARGET") or ""
            subject = r.get("SUBJECT") or "Notification"
            body = r.get("BODY") or ""
            result = "skipped"
            if channel == "SLACK" and self.slack_webhook:
                result = self._send_slack(target or self.slack_webhook, subject, body)
            elif channel == "EMAIL" and target:
                result = self._send_email(target, subject, body)
            snowflake_connector.execute_non_query(
                f"""
                UPDATE {DB}.DATA_GOVERNANCE.NOTIFICATIONS_OUTBOX
                   SET SENT_AT = CURRENT_TIMESTAMP, SENT_RESULT = %(res)s
                 WHERE ID = %(id)s
                """,
                {"res": result, "id": nid}
            )
            count += 1
        return count


notifier_service = NotifierService()
