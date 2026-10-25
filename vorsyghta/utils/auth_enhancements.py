"""Email verification and password reset enhancements for Vorsyghta auth."""

import hashlib
import secrets
import string
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from vorsyghta.db.models.auth import UserRecord


def generate_verification_token() -> str:
    """Generate a random verification token."""
    return secrets.token_urlsafe(32)


def is_valid_verification_token(token: str, db_session: Session, user: UserRecord) -> bool:
    """Check if a verification token is valid for the given user."""
    if not user.verification_token:
        return False
    return user.verification_token == token


def generate_reset_token() -> str:
    """Generate a random password reset token."""
    return secrets.token_urlsafe(32)


def is_valid_reset_token(token: str, db_session: Session, user: UserRecord) -> bool:
    """Check if a password reset token is valid for the given user."""
    if not user.reset_token:
        return False
    return user.reset_token == token


def send_verification_email(email: str, token: str, tenant_name: str = "") -> None:
    """Send verification email via SMTP to Mailpit."""
    verification_url = f"http://localhost:3000/verify-email?token={token}"
    subject = f"Verify your email for {tenant_name or 'Vorsyghta'}"
    body = f"<p>Hello,</p><p>Please verify your email by clicking the link below:</p><p><a href='{verification_url}'>Verify Email</a></p><p>Or use this token: {token}</p>"
    try:
        import smtplib
        import os
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        smtp_server = os.getenv("SMTP_SERVER", "mailpit")
        smtp_port = int(os.getenv("SMTP_PORT", "1025"))
        from_addr = os.getenv("SMTP_FROM_EMAIL", "noreply@vorsyghta.local")
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = email
        msg.attach(MIMEText(body, "html"))
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.send_message(msg)
        import logging
        logging.getLogger(__name__).info(f"Verification email sent to {email}")
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to send verification email to {email}: {e}")


def send_reset_email(email: str, token: str, tenant_name: str = "") -> None:
    """Send password reset email via SMTP to Mailpit."""
    reset_url = f"http://localhost:3000/reset-password?token={token}"
    subject = f"Reset your password for {tenant_name or 'Vorsyghta'}"
    body = f"<p>Hello,</p><p>Reset your password by clicking the link below:</p><p><a href='{reset_url}'>Reset Password</a></p><p>Or use this token: {token}</p>"
    try:
        import smtplib
        import os
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        smtp_server = os.getenv("SMTP_SERVER", "mailpit")
        smtp_port = int(os.getenv("SMTP_PORT", "1025"))
        from_addr = os.getenv("SMTP_FROM_EMAIL", "noreply@vorsyghta.local")
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = email
        msg.attach(MIMEText(body, "html"))
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.send_message(msg)
        import logging
        logging.getLogger(__name__).info(f"Password reset email sent to {email}")
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to send password reset email to {email}: {e}")
