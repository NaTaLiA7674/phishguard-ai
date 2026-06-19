import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

PESOS_AG = {
    "cuerpo_corto": 0.935,
    "accion_legal": 0.935,
    "instruccion_confidencialidad": 0.806,
    "palabras_clave_url": 0.806,
    "asunto_verificacion": 0.677,
    "url_con_ip": 0.613,
    "multiples_urls": 0.548,
    "dominio_externo": 0.355,
    "zona_horaria_inconsistente": 0.355,
    "mismatch_dominio_url": 0.355,
    "solo_enlace_sin_texto": 0.161,
    "solicita_credenciales": -0.032,
    "asunto_financiero": -0.097,
    "mezcla_idiomas": -0.097,
    "asunto_premio": -0.161,
    "solicita_datos_bancarios": -0.161,
    "ip_en_cuerpo": -0.161,
    "suplantacion_marca": -0.226,
    "destinatario_undisclosed": -0.226,
    "url_acortada": -0.355,
    "envio_madrugada": -0.355,
    "nombre_display_sospechoso": -0.355,
    "asunto_corto": -0.355,
    "errores_ortograficos": -0.419,
    "dominio_gratuito": -0.419,
    "asunto_urgencia": -0.484,
    "protocolo_http_inseguro": -0.484,
    "promesa_beneficio": -0.484,
    "telefono_detectado": -0.548,
    "fecha_limite": -0.548,
    "asunto_amenaza": -0.613,
    "apelacion_miedo": -0.871,
}

MAPEO_INDICES = [
    "dominio_externo", "nombre_display_sospechoso", "dominio_gratuito",
    "suplantacion_marca", "destinatario_undisclosed",
    "asunto_urgencia", "asunto_financiero", "asunto_premio", "asunto_amenaza",
    "asunto_verificacion", "asunto_corto",
    "envio_madrugada", "zona_horaria_inconsistente",
    "solicita_credenciales", "solicita_datos_bancarios", "errores_ortograficos",
    "mezcla_idiomas", "fecha_limite", "apelacion_miedo", "telefono_detectado",
    "cuerpo_corto", "solo_enlace_sin_texto", "promesa_beneficio",
    "accion_legal", "instruccion_confidencialidad", "ip_en_cuerpo",
    "url_acortada", "url_con_ip", "mismatch_dominio_url",
    "protocolo_http_inseguro", "palabras_clave_url", "multiples_urls",
]

FREE_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "mail.com",
]
BRANDS = [
    "google", "paypal", "bank", "banco", "apple", "microsoft", "amazon",
    "facebook", "netflix", "visa", "mastercard", "bbva", "santander",
    "atlassian", "jira",
]
SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co"]
URL_KEYWORDS = ["login", "verify", "secure", "update", "verificar", "acceso"]
URL_STOP = set(' \t\n\r"\'<>()[]{},')


def _extraer_de_json_str(s: str, clave: str) -> str:
    needle = '"' + clave + '"'
    idx = 0
    while True:
        pos = s.lower().find(needle.lower(), idx)
        if pos == -1:
            return ""
        tras_clave = s[pos + len(needle):].lstrip()
        if tras_clave.startswith(":"):
            break
        idx = pos + 1

    colon = s.find(":", pos + len(needle))
    open_q = s.find('"', colon + 1)
    if open_q == -1:
        return ""
    close_q = open_q + 1
    while close_q < len(s):
        if s[close_q] == '"' and s[close_q - 1] != "\\":
            break
        close_q += 1
    return s[open_q + 1: close_q]


def _parsear_headers(headers_raw: Any) -> Dict[str, str]:
    if isinstance(headers_raw, dict):
        return {str(k).lower(): str(v) for k, v in headers_raw.items()}

    s = str(headers_raw)
    if s.strip().startswith("{"):
        resultado = {}
        for clave in ["from", "date", "received", "return-path",
                       "authentication-results", "dkim-signature"]:
            val = _extraer_de_json_str(s, clave)
            if val:
                resultado[clave] = val
        if resultado:
            return resultado

    resultado = {}
    for linea in s.replace("\\r\\n", "\n").split("\n"):
        if ":" in linea:
            k, _, v = linea.partition(":")
            resultado[k.strip().lower()] = v.strip()
    return resultado


def _parsear_hora_y_zona(date_str: str) -> Tuple[Optional[int], Optional[int]]:
    hora = None
    offset_min = None
    for token in date_str.split():
        t = token.strip("();,")
        partes = t.split(":")
        if len(partes) == 3 and all(p.isdigit() for p in partes):
            try:
                h = int(partes[0])
                if 0 <= h <= 23:
                    hora = h
            except Exception:
                pass
        if len(t) == 5 and t[0] in "+-" and t[1:].isdigit():
            try:
                sign = 1 if t[0] == "+" else -1
                offset_min = sign * (int(t[1:3]) * 60 + int(t[3:5]))
            except Exception:
                pass
    return hora, offset_min


def _extraer_urls(texto: str) -> List[str]:
    urls = []
    visto = set()
    texto_l = texto.lower()

    for proto in ["http://", "https://"]:
        idx = 0
        while True:
            pos = texto_l.find(proto, idx)
            if pos == -1:
                break
            end = pos + len(proto)
            while end < len(texto) and texto[end] not in URL_STOP:
                end += 1
            url = texto[pos:end].rstrip(".,;:")
            if len(url) > len(proto) and url not in visto:
                urls.append(url)
                visto.add(url)
            idx = pos + len(proto)
    return urls


def _dominio_de_url(url: str) -> str:
    try:
        sin_proto = url.split("://", 1)[-1]
        host = sin_proto.split("/")[0].split("?")[0].split(":")[0].lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return ""


def _es_ip_valida(token: str) -> bool:
    partes = token.split(".")
    if len(partes) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in partes)


def _detectar_ip_en_texto(texto_lower: str) -> bool:
    for token in texto_lower.split():
        limpia = token.strip("\"'<>()[]{},;:/?=&#")
        if _es_ip_valida(limpia):
            return True
    return False


def _contiene_alguna(lista_palabras: List[str], texto_lower: str) -> bool:
    for palabra in lista_palabras:
        if palabra in texto_lower:
            return True
    return False


def evaluate(email_data: Dict[str, Any]) -> Dict[str, Any]:
    html_body = str(email_data.get("htmlBody", ""))
    text_body = str(email_data.get("textBody", ""))
    subject = str(email_data.get("subject", ""))
    recipient = str(email_data.get("recipient", ""))
    headers_raw = email_data.get("headers", {})

    if not html_body and not text_body and not subject and not recipient:
        return {"score": 50.0, "genes_implicados": [], "suma_lineal_ag": 0.0}

    subject_lower = subject.lower()
    recipient_lower = recipient.lower()
    full_body = text_body + " " + html_body
    full_body_lower = full_body.lower()

    hd = _parsear_headers(headers_raw)
    from_val = hd.get("from", "")
    date_val = hd.get("date", "")
    from_str = from_val.split(":", 1)[-1].strip() if ":" in from_val else from_val
    date_str = date_val.split(":", 1)[-1].strip() if ":" in date_val else date_val

    sender_email = sender_dominio = sender_display = ""
    from_lower = from_str.lower()
    if "<" in from_lower and ">" in from_lower:
        sender_display = from_lower.split("<")[0].strip().strip('"').strip("'")
        sender_email = from_lower.split("<")[-1].split(">")[0].strip()
    elif "@" in from_lower:
        sender_email = from_lower.strip()
    if "@" in sender_email:
        sender_dominio = sender_email.split("@")[-1].strip()

    receiver_dominio = ""
    if "@" in recipient_lower:
        receiver_dominio = recipient_lower.split("@")[-1].split(">")[0].strip()

    urls_en_cuerpo = _extraer_urls(full_body)
    dominios_url = [_dominio_de_url(u) for u in urls_en_cuerpo]

    genes = [0] * 32

    if sender_dominio and receiver_dominio:
        genes[0] = int(sender_dominio != receiver_dominio)

    if sender_display and sender_dominio:
        for m in BRANDS:
            if m in sender_display and m not in sender_dominio:
                genes[1] = 1
                break

    if sender_dominio:
        genes[2] = int(any(fd in sender_dominio for fd in FREE_DOMAINS))

    if sender_dominio:
        for m in BRANDS:
            menciona = (m in sender_display) or (m in sender_dominio)
            oficial = sender_dominio in (m + ".com", m + ".co")
            if menciona and not oficial:
                genes[3] = 1
                break

    genes[4] = int(not recipient_lower or "undisclosed" in recipient_lower)

    genes[5] = int(_contiene_alguna(
        ["urgent", "urgente", "immediate", "inmediato", "now", "ahora"], subject_lower))
    genes[6] = int(_contiene_alguna(
        ["bank", "banco", "payment", "pago", "account", "cuenta"], subject_lower))
    genes[7] = int(_contiene_alguna(
        ["winner", "ganador", "prize", "premio", "lottery"], subject_lower))
    genes[8] = int(_contiene_alguna(
        ["blocked", "bloqueo", "warning", "suspended", "lose"], subject_lower))
    genes[9] = int(_contiene_alguna(
        ["verify", "verificar", "confirm", "confirmar", "update", "validar"], subject_lower))
    genes[10] = int(len(subject.strip()) < 5)

    hora, offset_min = _parsear_hora_y_zona(date_str)
    if hora is not None:
        genes[11] = int(0 <= hora < 5)
    if offset_min is not None:
        genes[12] = int(not (-720 <= offset_min <= 840) or offset_min % 30 != 0)

    genes[13] = int(_contiene_alguna(
        ["password", "login", "credenciales", "acceso", "contrasena", "contraseña"], full_body_lower))
    genes[14] = int(_contiene_alguna(
        ["credit card", "tarjeta", "cvv", "cuenta", "debito", "débito"], full_body_lower))
    genes[15] = int("!!" in full_body_lower or "??" in full_body_lower or "..." in full_body_lower)

    tiene_es = _contiene_alguna(
        ["urgente", "banco", "cuenta", "verificar", "premio", "gratis"], full_body_lower)
    tiene_en = _contiene_alguna(
        ["urgent", "bank", "account", "verify", "prize", "free"], full_body_lower)
    genes[16] = int(tiene_es and tiene_en)

    genes[17] = int(_contiene_alguna(
        ["deadline", "expires", "expira", "days", "hours"], full_body_lower))
    genes[18] = int(_contiene_alguna(
        ["fear", "perder", "riesgo", "warning", "lose"], full_body_lower))

    tiene_telefono = 0
    for token in full_body_lower.split():
        solo_digitos = "".join(c for c in token if c.isdigit())
        if len(solo_digitos) >= 8:
            tiene_telefono = 1
            break
    genes[19] = tiene_telefono

    body_para_contar = text_body if text_body.strip() else html_body
    n_palabras = len(body_para_contar.split())
    genes[20] = int(n_palabras < 50)

    if len(urls_en_cuerpo) == 1:
        texto_sin_url = full_body
        for u in urls_en_cuerpo:
            texto_sin_url = texto_sin_url.replace(u, "")
        genes[21] = int(len(texto_sin_url.split()) < 15)

    genes[22] = int(_contiene_alguna(
        ["free", "gratis", "bonus", "reward", "recompensa", "beneficio"], full_body_lower))
    genes[23] = int(_contiene_alguna(
        ["court", "legal", "juzgado", "demanda", "lawsuit", "tribunal"], full_body_lower))
    genes[24] = int(_contiene_alguna(
        ["do not forward", "no reenviar", "confidential", "confidencial"], full_body_lower))
    genes[25] = int(_detectar_ip_en_texto(full_body_lower))

    url_acortada = url_con_ip = url_palabras_clave = 0
    for u in urls_en_cuerpo:
        u_l = u.lower()
        if any(sh in u_l for sh in SHORTENERS):
            url_acortada = 1
        host = _dominio_de_url(u_l)
        if _es_ip_valida(host):
            url_con_ip = 1
        if any(kw in u_l for kw in URL_KEYWORDS):
            url_palabras_clave = 1

    genes[26] = url_acortada
    genes[27] = url_con_ip

    if sender_dominio and dominios_url:
        for d in dominios_url:
            if d and sender_dominio not in d and d not in sender_dominio:
                genes[28] = 1
                break

    genes[29] = int("http://" in full_body_lower)
    genes[30] = url_palabras_clave
    genes[31] = int(len(urls_en_cuerpo) > 3)

    suma_lineal_ag = 0.0
    genes_implicados = []
    for pos, nombre in enumerate(MAPEO_INDICES):
        if genes[pos] == 1:
            peso = PESOS_AG.get(nombre, 0.0)
            suma_lineal_ag += peso
            genes_implicados.append({"caracteristica": nombre, "peso": peso})

    try:
        e = 2.718281828459 ** (-suma_lineal_ag)
        score_mapeado = (1.0 / (1.0 + e)) * 100.0
    except Exception:
        score_mapeado = 100.0 if suma_lineal_ag > 0 else 0.0

    return {
        "score": round(score_mapeado, 2),
        "genes_implicados": genes_implicados,
        "suma_lineal_ag": round(suma_lineal_ag, 4),
    }
