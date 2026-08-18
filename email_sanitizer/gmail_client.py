"""
email_sanitizer.gmail_client
==============================

Thin wrapper around the Gmail API: search + fetch + extract body text.
Deliberately does nothing else — no send, no delete, no modify. The OAuth
scope requested in gmail_auth.py (gmail.readonly) enforces that at the
account-permission level too, so even a bug here can't turn into a
send/delete action.
"""

import base64
from typing import Optional

from googleapiclient.discovery import build

from .gmail_auth import get_credentials


def _get_service():
    creds = get_credentials()
    return build("gmail", "v1", credentials=creds)


def _extract_body(payload: dict) -> str:
    """Pull plain-text (preferred) or HTML body out of a Gmail message payload."""

    def decode(data: str) -> str:
        return base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="replace")

    # Simple message: body directly on the payload.
    if payload.get("body", {}).get("data"):
        return decode(payload["body"]["data"])

    # Multipart message: walk parts, prefer text/plain, fall back to text/html.
    plain_text = None
    html_text = None

    def walk(parts):
        nonlocal plain_text, html_text
        for part in parts:
            mime = part.get("mimeType", "")
            body_data = part.get("body", {}).get("data")
            if mime == "text/plain" and body_data and plain_text is None:
                plain_text = decode(body_data)
            elif mime == "text/html" and body_data and html_text is None:
                html_text = decode(body_data)
            if "parts" in part:
                walk(part["parts"])

    walk(payload.get("parts", []))
    return plain_text or html_text or ""


def search_messages(query: str, max_results: int = 5) -> list[dict]:
    """
    Search Gmail and return a list of {id, subject, from, snippet} — metadata
    only, no bodies. Use fetch_message_sanitized() to get actual content.
    """
    service = _get_service()
    results = (
        service.users()
        .messages()
        .list(userId="me", q=query, maxResults=max_results)
        .execute()
    )
    messages = results.get("messages", [])

    summaries = []
    for msg in messages:
        full = (
            service.users()
            .messages()
            .get(userId="me", id=msg["id"], format="metadata",
                 metadataHeaders=["Subject", "From"])
            .execute()
        )
        headers = {h["name"]: h["value"] for h in full.get("payload", {}).get("headers", [])}
        summaries.append({
            "id": msg["id"],
            "subject": headers.get("Subject", "(no subject)"),
            "from": headers.get("From", "(unknown sender)"),
            "snippet": full.get("snippet", ""),
        })
    return summaries


def fetch_raw_body(message_id: str) -> str:
    """Fetch the raw, UNSANITIZED body of a single message. Internal use only —
    callers outside this module should use fetch_message_sanitized() in
    mcp_server.py instead, so raw content never leaves this layer."""
    service = _get_service()
    message = service.users().messages().get(userId="me", id=message_id, format="full").execute()
    return _extract_body(message.get("payload", {}))
