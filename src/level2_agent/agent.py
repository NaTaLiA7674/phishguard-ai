import os
import logging
from typing import Optional

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.runnables import RunnablePassthrough, RunnableLambda
from langchain_core.messages import HumanMessage

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
from .prompts import build_chat_prompt
from .tools import create_retriever
from .memory import get_chat_history

load_dotenv()
logger = logging.getLogger(__name__)

llm: Optional[ChatGoogleGenerativeAI] = None
analysis_chain = None


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


def _build_analysis_chain():
    prompt = build_chat_prompt()
    parser = JsonOutputParser(pydantic_object=PhishingReport)
    model = _ensure_llm()

    try:
        retriever = create_retriever()
    except Exception as e:
        logger.warning("No se pudo crear el retriever RAG: %s", e)
        retriever = None

    def _get_context(inputs: dict) -> str:
        if retriever is None:
            return "No disponible. Procede con tu conocimiento base."
        try:
            query = f"{inputs.get('subject', '')} {inputs.get('htmlBody', '')[:500]}"
            docs = retriever.invoke(query)
            if not docs:
                return "No se encontraron documentos relevantes en la base vectorial."
            return "\n\n".join(doc.page_content for doc in docs)
        except Exception as e:
            logger.warning("Error al recuperar contexto RAG: %s", e)
            return "Error al consultar la base vectorial. Procede con tu conocimiento base."

    chain = (
        RunnablePassthrough.assign(context=RunnableLambda(_get_context))
        | prompt
        | model
        | parser
    )
    return chain


def _get_chain():
    global analysis_chain
    if analysis_chain is None:
        analysis_chain = _build_analysis_chain()
    return analysis_chain


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

    logger.info("Score %s entre %s-%s → ruta AI Agent", score, SCORE_UMBRAL_BAJO, SCORE_UMBRAL_ALTO)

    chain = _get_chain()

    chat_history = get_chat_history(email_data.message_id)

    chain_input = {
        "htmlBody": email_data.htmlBody,
        "headers": email_data.headers,
        "subject": email_data.subject,
        "history": chat_history.messages,
    }

    try:
        result = chain.invoke(chain_input)
        chat_history.add_user_message(
            HumanMessage(content=f"Analizar correo: {email_data.subject}")
        )
        return result
    except Exception as e:
        logger.error("Error en AI Agent chain: %s", e)
        raise
