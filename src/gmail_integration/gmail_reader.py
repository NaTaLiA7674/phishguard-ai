import base64
import email
import logging

from googleapiclient.discovery import build

logger = logging.getLogger(__name__)


def get_gmail_service(creds):
    return build("gmail", "v1", credentials=creds)


def list_unread_messages(service, max_results=10):
    results = service.users().messages().list(
        userId="me", q="is:unread", maxResults=max_results
    ).execute()
    messages = results.get("messages", [])
    return [msg["id"] for msg in messages]


def get_message_details(service, msg_id):
    msg = service.users().messages().get(
        userId="me", id=msg_id, format="raw"
    ).execute()

    raw_data = msg["raw"]
    msg_bytes = base64.urlsafe_b64decode(raw_data.encode("ASCII"))
    mime_msg = email.message_from_bytes(msg_bytes)

    subject = str(mime_msg.get("Subject", ""))
    sender = mime_msg.get("From", "")
    recipient = mime_msg.get("To", "")
    date = mime_msg.get("Date", "")
    message_id = mime_msg.get("Message-ID", msg_id)

    headers_json = str({
        "from": sender,
        "to": recipient,
        "date": date,
        "subject": subject,
        "message_id": message_id,
    })

    html_body = ""
    text_body = ""

    if mime_msg.is_multipart():
        for part in mime_msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html_body = payload.decode("utf-8", errors="replace")
            elif content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    text_body = payload.decode("utf-8", errors="replace")
    else:
        content_type = mime_msg.get_content_type()
        payload = mime_msg.get_payload(decode=True)
        if payload:
            decoded = payload.decode("utf-8", errors="replace")
            if content_type == "text/html":
                html_body = decoded
            else:
                text_body = decoded

    return {
        "subject": subject,
        "recipient": recipient.split("<")[-1].split(">")[0].strip() if "<" in recipient else recipient.strip(),
        "headers": headers_json,
        "textBody": text_body,
        "htmlBody": html_body,
        "message_id": message_id,
    }


def mark_as_read(service, msg_id):
    service.users().messages().modify(
        userId="me", id=msg_id, body={"removeLabelIds": ["UNREAD"]}
    ).execute()


def move_to_label(service, msg_id, label_name="Phishing Alertas"):
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    label_id = None
    for lbl in labels:
        if lbl["name"] == label_name:
            label_id = lbl["id"]
            break

    if not label_id:
        label = service.users().labels().create(
            userId="me", body={"name": label_name}
        ).execute()
        label_id = label["id"]

    service.users().messages().modify(
        userId="me", id=msg_id,
        body={"addLabelIds": [label_id], "removeLabelIds": ["UNREAD"]}
    ).execute()
