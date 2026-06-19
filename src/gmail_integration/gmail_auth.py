import os
import json
import logging
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

logger = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly",
          "https://www.googleapis.com/auth/gmail.modify"]


def authenticate_gmail() -> Credentials:
    creds = None
    token_path = os.path.join(os.path.dirname(__file__), "..", "..", "token.json")
    creds_path = os.path.join(os.path.dirname(__file__), "..", "..", "credenciales.json")

    if os.path.exists(token_path):
        with open(token_path, "r") as f:
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(creds_path):
                raise FileNotFoundError(
                    "No se encuentra credenciales.json. "
                    "Descárgalo desde Google Cloud Console y colócalo en la raíz del proyecto."
                )
            flow = InstalledAppFlow.from_client_secrets_file(creds_path, SCOPES)
            creds = flow.run_local_server(port=0)

        with open(token_path, "w") as f:
            f.write(creds.to_json())
        logger.info("Token guardado en %s", token_path)

    return creds
