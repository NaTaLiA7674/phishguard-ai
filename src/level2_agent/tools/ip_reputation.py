import os
import json
import logging
from typing import Optional
import requests
from langchain_core.tools import StructuredTool

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15


def check_ip_reputation(target: str) -> str:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return "Error: VT_API_KEY no está configurada. No se pudo verificar la reputación."

    is_ip = all(p.isdigit() for p in target.split(".")) and target.count(".") == 3
    endpoint = f"{VT_BASE_URL}/ip_addresses/{target}" if is_ip else f"{VT_BASE_URL}/urls/{target}"

    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        if not is_ip:
            import base64
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            endpoint = f"{VT_BASE_URL}/urls/{url_id}"

        resp = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 429:
            logger.warning("VirusTotal rate limit excedido para: %s", target)
            return "Reputación no disponible: límite de consultas excedido (rate limit)."

        if resp.status_code == 404:
            return f"No se encontró información de reputación para: {target}"

        if resp.status_code != 200:
            logger.warning("VirusTotal error %s para %s: %s", resp.status_code, target, resp.text[:200])
            return f"Error al consultar reputación de {target} (HTTP {resp.status_code})."

        data = resp.json()
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        harmless = last_analysis.get("harmless", 0)
        undetected = last_analysis.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        result = {
            "target": target,
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "total_engines_scanned": total,
            "harmless_engines": harmless,
        }

        if malicious > 0:
            result["threat_level"] = "alta" if malicious >= 5 else "media"
            result["assessment"] = f"⚠️ Posible amenaza: {malicious}/{total} motores detectaron este recurso como malicioso."
        elif suspicious > 0:
            result["threat_level"] = "baja"
            result["assessment"] = f"⚠️ Sospechoso: {suspicious} motores reportan actividad sospechosa."
        else:
            result["threat_level"] = "ninguna"
            result["assessment"] = f"✅ Recurso limpio: {harmless}/{total} motores lo clasifican como seguro."

        return json.dumps(result, ensure_ascii=False, indent=2)

    except requests.exceptions.Timeout:
        logger.warning("Timeout al consultar VirusTotal para: %s", target)
        return f"Reputación no disponible: tiempo de espera agotado para {target}."
    except requests.exceptions.ConnectionError:
        logger.warning("Error de conexión con VirusTotal para: %s", target)
        return f"Reputación no disponible: error de conexión con VirusTotal."
    except Exception as e:
        logger.error("Error inesperado en VirusTotal para %s: %s", target, e)
        return f"Error inesperado al consultar reputación de {target}: {e}"


ip_reputation_tool = StructuredTool.from_function(
    name="check_ip_reputation",
    description="""Consulta la reputación de una dirección IP o URL en VirusTotal.
    Útil para verificar si un dominio, IP o enlace ha sido reportado como malicioso.
    Recibe como input una dirección IP (ej: 192.168.1.1) o una URL completa (ej: http://evil.com/login).
    Devuelve el número de detecciones maliciosas y el total de motores analizados.""",
    func=check_ip_reputation,
)
