import base64

from email_sanitizer.gmail_client import _extract_body


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8")


def test_extract_body_simple_payload():
    payload = {"body": {"data": _b64("Hello, this is a simple email.")}}
    assert _extract_body(payload) == "Hello, this is a simple email."


def test_extract_body_prefers_plain_text_over_html():
    payload = {
        "parts": [
            {"mimeType": "text/html", "body": {"data": _b64("<p>HTML version</p>")}},
            {"mimeType": "text/plain", "body": {"data": _b64("Plain text version")}},
        ]
    }
    assert _extract_body(payload) == "Plain text version"


def test_extract_body_falls_back_to_html_if_no_plain_text():
    payload = {
        "parts": [
            {"mimeType": "text/html", "body": {"data": _b64("<p>Only HTML here</p>")}},
        ]
    }
    assert _extract_body(payload) == "<p>Only HTML here</p>"


def test_extract_body_walks_nested_multipart():
    payload = {
        "parts": [
            {
                "mimeType": "multipart/alternative",
                "parts": [
                    {"mimeType": "text/plain", "body": {"data": _b64("Nested plain text")}},
                ],
            }
        ]
    }
    assert _extract_body(payload) == "Nested plain text"


def test_extract_body_empty_payload_returns_empty_string():
    assert _extract_body({}) == ""
