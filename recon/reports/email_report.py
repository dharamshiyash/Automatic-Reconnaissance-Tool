"""
recon.reports.email_report — Email report sender.

Sends reconnaissance reports as email attachments using SMTP.
"""

from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from typing import Optional

from recon.config import Config
from recon.logger import get_logger

logger = get_logger(__name__)


def send(
    recipient: str,
    subject: str,
    body: str,
    attachments: list[str],
    config: Optional[Config] = None,
) -> tuple[bool, Optional[str]]:
    """Send an email with report attachments.

    Args:
        recipient: Recipient email address.
        subject: Email subject line.
        body: Plain-text email body.
        attachments: List of file paths to attach.
        config: Optional Config for SMTP credentials.

    Returns:
        Tuple of (success, error_message).
    """
    cfg = config or Config()

    if not cfg.smtp_user or not cfg.smtp_pass:
        return False, "SMTP credentials not configured. Set them in .env"

    msg = EmailMessage()
    msg["From"] = cfg.smtp_user
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    # Attach files
    for filepath in attachments:
        if not os.path.exists(filepath):
            logger.warning("Attachment not found: %s", filepath)
            continue
        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
            fname = os.path.basename(filepath)
            if fname.lower().endswith(".pdf"):
                maintype, subtype = "application", "pdf"
            elif fname.lower().endswith(".html"):
                maintype, subtype = "application", "html"
            elif fname.lower().endswith(".json"):
                maintype, subtype = "application", "json"
            else:
                maintype, subtype = "application", "octet-stream"
            msg.add_attachment(
                data,
                maintype=maintype,
                subtype=subtype,
                filename=fname,
            )
            logger.info("Attached: %s", fname)
        except Exception as exc:
            return False, f"Attachment error ({filepath}): {exc}"

    # Send
    try:
        server = smtplib.SMTP(cfg.smtp_server, cfg.smtp_port, timeout=20)
        if cfg.smtp_use_tls:
            server.starttls()
        server.login(cfg.smtp_user, cfg.smtp_pass)
        server.send_message(msg)
        server.quit()
        logger.info("Email sent to %s", recipient)
        return True, None
    except Exception as exc:
        logger.error("Email send failed: %s", exc)
        return False, str(exc)
