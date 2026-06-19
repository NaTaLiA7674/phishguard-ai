import os
import re
import logging
from typing import Optional

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.tools import StructuredTool
from langgraph.prebuilt import create_react_agent

from .models import (
    EmailData,
    PhishingReport,
    SCORE_UMBRAL_BAJO,
    SCORE_UMBRAL_ALTO,
    SCORE_FALLBACK,
    SEVERIDAD_BAJO,
    SEVERIDAD_CRITICO,
    SEVERIDAD_ALTO,
)
from .prompts import _build_system_prompt, HUMAN_TEMPLATE
from .tools import create_retriever
from .tools.ip_reputation import ip_reputation_tool
from .tools.jira_integration import create_jira_ticket
from .memory import get_chat_history

load_dotenv()
logger = logging.getLogger(__name__)

llm: Optional[ChatGoogleGenerativeAI] = None
react_agent = None


def _ensure_llm():
    global llm
    if llm is None:
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY no está configurada")
        llm = ChatGoogleGenerativeAI(
            model="models/gemini-2.5-flash-lite",
            temperature=0,
        )
    return llm


def _create_rag_tool() -> StructuredTool:
    def _rag_search(query: str) -> str:
        try:
            retriever = create_retriever()
        except Exception as e:
            logger.warning("No se pudo crear el retriever RAG: %s", e)
            return "No disponible. Procede con tu conocimiento base."
        try:
            docs = retriever.invoke(query)
            if not docs:
                return "No se encontraron documentos relevantes en la base vectorial."
            return "\n\n".join(doc.page_content for doc in docs)
        except Exception as e:
            logger.warning("Error al recuperar contexto RAG: %s", e)
            return "Error al consultar la base vectorial. Procede con tu conocimiento base."

    return StructuredTool.from_function(
        name="consultar_base_vectorial",
        description=(
            "Consulta la base de datos vectorial de ciberseguridad "
            "(NIST SP 800-53 / OWASP) buscando controles y guías "
            "relacionados con patrones de phishing. Recibe una consulta "
            "textual descriptiva y devuelve documentos relevantes."
        ),
        func=_rag_search,
    )


def _build_react_agent():
    model = _ensure_llm()

    tools = []
    try:
        tools.append(_create_rag_tool())
    except Exception as e:
        logger.warning("No se pudo crear el RAG tool: %s", e)

    if os.getenv("VT_API_KEY"):
        tools.append(ip_reputation_tool)

    agent = create_react_agent(
        model=model,
        tools=tools,
        prompt=_build_system_prompt(),
    )
    return agent


def _get_react_agent():
    global react_agent
    if react_agent is None:
        react_agent = _build_react_agent()
    return react_agent


def _parse_agent_response(ai_content: str) -> PhishingReport:
    parser = JsonOutputParser(pydantic_object=PhishingReport)

    content = ai_content.strip()
    if content.startswith("```json"):
        content = content[7:]
    elif content.startswith("```"):
        content = content[3:]
    if content.endswith("```"):
        content = content[:-3]
    content = content.strip()

    try:
        data = parser.invoke(content)
        if isinstance(data, dict):
            return PhishingReport(**data)
        return data
    except Exception:
        pass

    json_match = re.search(r"\{.*\}", content, re.DOTALL)
    if json_match:
        try:
            data = parser.invoke(json_match.group())
            if isinstance(data, dict):
                return PhishingReport(**data)
            return data
        except Exception:
            pass

    raise ValueError(
        f"No se pudo extraer un JSON válido: {content[:500]}"
    )


def _genetic_score(email_data: EmailData) -> dict:
    try:
        from level3_logic.genetic_logic import evaluate as genetic_evaluate
        data = {
            "htmlBody": email_data.htmlBody,
            "textBody": email_data.textBody,
            "subject": email_data.subject,
            "recipient": email_data.recipient,
            "headers": email_data.headers,
        }
        result = genetic_evaluate(data)
        return result
    except ImportError:
        logger.warning("level3_logic.genetic_logic no disponible. Usando score fallback=%s", SCORE_FALLBACK)
        return {"score": SCORE_FALLBACK, "genes_implicados": []}
    except Exception as e:
        logger.error("Error en genetic_logic: %s. Usando score fallback=%s", e, SCORE_FALLBACK)
        return {"score": SCORE_FALLBACK, "genes_implicados": []}


def generate_benign_report(score: float) -> PhishingReport:
    return PhishingReport(
        resumen="Tráfico seguro confirmado: Notificación automatizada del sistema que clasifica el correo electrónico como mensaje legítimo.",
        analisis_tecnico=f"Evaluación inicial satisfactoria. El score de riesgo obtenido es de {score:.0f}/100, manteniéndose por debajo del umbral de sospecha ({SCORE_UMBRAL_BAJO}/100).",
        indicadores_phishing=[],
        es_phishing=False,
        nivel_severidad=SEVERIDAD_BAJO,
        justificacion_veredicto="El mensaje superó exitosamente los controles de filtrado perimetral del Algoritmo Genético. No se observaron patrones de ingeniería social, ni anomalías críticas en las firmas de autenticación técnica analizadas en las cabeceras. Se autoriza su entrega ordinaria al usuario.",
    )


def generate_malicious_report(score: float, genes: list) -> PhishingReport:
    formato_evidencia = "\n".join(
        f"- Indicador activado: {g.get('caracteristica', g)}" for g in genes
    )
    severidad = SEVERIDAD_CRITICO if score >= 90 else SEVERIDAD_ALTO

    return PhishingReport(
        resumen="Alerta perimetral automática: El correo electrónico ha sido interceptado y clasificado directamente como amenaza debido a un índice de riesgo crítico.",
        analisis_tecnico=f"Análisis algorítmico completado. El correo electrónico arrojó un score acumulado de {score:.0f}/100, superando el umbral de seguridad tolerado ({SCORE_UMBRAL_ALTO}/100).",
        es_phishing=True,
        indicadores_phishing=[g.get("caracteristica", str(g)) for g in genes],
        nivel_severidad=severidad,
        justificacion_veredicto=f"Bloqueo automatizado preventivo por el pipeline del SOC.\n\nLa optimización polinomial basada en Algoritmos Genéticos determinó que la concurrencia de los siguientes factores representa un peligro inminente de fraude o fuga de credenciales:\n\n{formato_evidencia}\n\nEl mensaje ha sido desviado de la bandeja del usuario de forma inmediata como medida de mitigación.",
    )


def analyze_email(email_data: EmailData) -> PhishingReport:
    _ensure_llm()

    genetic_result = _genetic_score(email_data)
    score = genetic_result["score"]
    genes = genetic_result.get("genes_implicados", [])

    if score < SCORE_UMBRAL_BAJO:
        logger.info("Score %s < %s → ruta benigna", score, SCORE_UMBRAL_BAJO)
        return generate_benign_report(score)

    if score > SCORE_UMBRAL_ALTO:
        logger.info("Score %s > %s → ruta maliciosa", score, SCORE_UMBRAL_ALTO)
        return generate_malicious_report(score, genes)

    logger.info("Score %s entre %s-%s → ruta AI Agent (ReAct)", score, SCORE_UMBRAL_BAJO, SCORE_UMBRAL_ALTO)

    agent = _get_react_agent()
    chat_history = get_chat_history(email_data.message_id)

    human_content = HUMAN_TEMPLATE.format(
        subject=email_data.subject,
        htmlBody=email_data.htmlBody,
        headers=email_data.headers,
    )

    messages = [HumanMessage(content=human_content)]

    try:
        result = agent.invoke({"messages": messages})

        final_msg = result["messages"][-1]
        if not isinstance(final_msg, AIMessage):
            for msg in reversed(result["messages"]):
                if isinstance(msg, AIMessage):
                    final_msg = msg
                    break

        logger.debug("Agent final_msg type=%s content=%s", type(final_msg).__name__, final_msg.content[:500] if final_msg.content else "(empty)")
        report = _parse_agent_response(final_msg.content)

        chat_history.add_user_message(
            HumanMessage(content=f"Analizar correo: {email_data.subject}")
        )
        chat_history.add_ai_message(final_msg.content)

        if report.es_phishing:
            jira_result = create_jira_ticket(report)
            logger.info("Resultado ticket Jira: %s", jira_result)

        return report
    except Exception as e:
        logger.error("Error en ReAct Agent: %s", e)
        raise
