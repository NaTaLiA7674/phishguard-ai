import os
import json
import logging
from typing import Optional
import requests
from ..models import PhishingReport

logger = logging.getLogger(__name__)

JIRA_API_TIMEOUT = 15


def create_jira_ticket(report: PhishingReport) -> dict:
    url = os.getenv("JIRA_INSTANCE_URL")
    email = os.getenv("JIRA_USER_EMAIL")
    token = os.getenv("JIRA_API_TOKEN")

    if not url or not email or not token:
        logger.warning("Credenciales de Jira incompletas. Saltando creación de ticket.")
        return {"success": False, "error": "Jira credentials not configured"}

    api_endpoint = f"{url.rstrip('/')}/rest/api/2/issue"
    auth = (email, token)

    summary = f"[SOC] Phishing Report: {report.resumen[:170]}"
    description = f"""h2. Resumen del Análisis

{report.resumen}

h2. Análisis Técnico

{report.analisis_tecnico}

h2. Indicadores de Phishing
{chr(10).join(f'* {i}' for i in report.indicadores_phishing) if report.indicadores_phishing else '* Ninguno'}

h2. Nivel de Severidad

*{report.nivel_severidad}*

h2. Justificación del Veredicto

{report.justificacion_veredicto}
"""

    payload = {
        "fields": {
            "project": {"key": "SEC"},
            "issuetype": {"name": "Task"},
            "summary": summary[:190],
            "description": description,
        }
    }

    try:
        resp = requests.post(
            api_endpoint,
            json=payload,
            auth=auth,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=JIRA_API_TIMEOUT,
        )

        if resp.status_code == 201:
            issue_key = resp.json().get("key", "unknown")
            logger.info("Ticket Jira creado exitosamente: %s", issue_key)
            return {"success": True, "issue_key": issue_key, "url": f"{url.rstrip('/')}/browse/{issue_key}"}

        logger.error("Error al crear ticket Jira: HTTP %s - %s", resp.status_code, resp.text[:300])
        return {"success": False, "error": f"Jira API returned HTTP {resp.status_code}: {resp.text[:200]}"}

    except requests.exceptions.ConnectionError:
        logger.error("No se pudo conectar con Jira en: %s", url)
        return {"success": False, "error": f"Cannot connect to Jira at {url}"}
    except requests.exceptions.Timeout:
        logger.error("Timeout al conectar con Jira")
        return {"success": False, "error": "Jira connection timeout"}
    except Exception as e:
        logger.error("Error inesperado al crear ticket Jira: %s", e)
        return {"success": False, "error": str(e)}
