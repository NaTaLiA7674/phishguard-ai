from src.level2_agent.models import EmailData


def gmail_to_emaildata(gmail_msg: dict) -> EmailData:
    return EmailData(
        subject=gmail_msg["subject"],
        recipient=gmail_msg["recipient"],
        headers=gmail_msg["headers"],
        textBody=gmail_msg["textBody"],
        htmlBody=gmail_msg["htmlBody"],
        message_id=gmail_msg["message_id"],
    )
