"""
email_sanitizer.gmail_auth
============================

Run this ONCE to authorize this tool against your own Gmail account.

Prerequisites:
    1. Go to https://console.cloud.google.com/ and create a project (or use
       an existing one).
    2. Enable the "Gmail API" for that project (APIs & Services > Library).
    3. Go to APIs & Services > Credentials > Create Credentials > OAuth
       client ID. Choose "Desktop app" as the application type.
    4. Download the resulting JSON file, rename it to `credentials.json`,
       and place it in this project's root directory (next to pyproject.toml).

Then run:
    python -m email_sanitizer.gmail_auth

This opens a browser window for you to log in and approve READ-ONLY access
(scope: gmail.readonly — this tool can never send, delete, or modify
anything in your account). It saves a `token.json` file locally so you
only have to do this once. Keep both credentials.json and token.json out
of version control (already covered in .gitignore).
"""

import os

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Read-only scope, on purpose: this tool should never be able to send,
# delete, or modify email. Least-privilege by design.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

CREDENTIALS_PATH = os.path.join(os.path.dirname(__file__), "..", "credentials.json")
TOKEN_PATH = os.path.join(os.path.dirname(__file__), "..", "token.json")


def get_credentials() -> Credentials:
    """Load cached credentials, refreshing or running the OAuth flow as needed."""
    creds = None

    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDENTIALS_PATH):
                raise FileNotFoundError(
                    "credentials.json not found. See the setup instructions "
                    "at the top of email_sanitizer/gmail_auth.py."
                )
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)

        with open(TOKEN_PATH, "w") as token_file:
            token_file.write(creds.to_json())

    return creds


if __name__ == "__main__":
    get_credentials()
    print("✅ Authorized. token.json saved — you won't need to log in again.")
    print("Scope granted: gmail.readonly (read-only, cannot send/delete/modify).")
