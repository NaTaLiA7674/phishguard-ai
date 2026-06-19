import os
import sys
import time
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

from src.gmail_integration.gmail_auth import authenticate_gmail
from src.gmail_integration.gmail_reader import (
    get_gmail_service,
    list_unread_messages,
    get_message_details,
    mark_as_read,
    move_to_label,
)
from src.gmail_integration.email_to_emaildata import gmail_to_emaildata
from src.level2_agent.agent import analyze_email

POLL_INTERVAL = 30


def process_message(service, msg_id):
    try:
        raw_msg = get_message_details(service, msg_id)
        email_data = gmail_to_emaildata(raw_msg)
        logger.info("Analizando correo: %s", email_data.subject)
        report = analyze_email(email_data)

        if report.es_phishing:
            subject_preview = email_data.subject[:50]
            logger.info(
                "PHISHING DETECTADO - Asunto: %s | Severidad: %s | Indicadores: %s",
                subject_preview,
                report.nivel_severidad,
                ", ".join(report.indicadores_phishing[:3]),
            )
            move_to_label(service, msg_id, "Phishing Alertas")
        else:
            logger.info("SEGURO - Asunto: %s", email_data.subject[:50])
            mark_as_read(service, msg_id)
    except Exception as e:
        logger.error("Error procesando mensaje %s: %s", msg_id, e)


def poll_loop():
    logger.info("Iniciando Gmail Poller...")
    creds = authenticate_gmail()
    service = get_gmail_service(creds)
    logger.info("Conectado a Gmail. Revisando cada %s segundos...", POLL_INTERVAL)

    while True:
        try:
            msg_ids = list_unread_messages(service, max_results=5)
            if msg_ids:
                logger.info("Encontrados %s correos nuevos", len(msg_ids))
                for msg_id in msg_ids:
                    process_message(service, msg_id)
            else:
                logger.debug("Sin correos nuevos")
        except Exception as e:
            logger.error("Error en ciclo de polling: %s", e)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    poll_loop()
