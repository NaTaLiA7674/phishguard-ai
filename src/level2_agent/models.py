from pydantic import BaseModel, Field
from typing import List, Optional


class EmailData(BaseModel):
    htmlBody: str = Field(description="Cuerpo del correo en formato HTML")
    headers: str = Field(description="Cabeceras completas del correo en JSON string")
    subject: str = Field(description="Asunto del correo")
    recipient: str = Field(description="Dirección de correo del destinatario (to.text)")
    textBody: str = Field(description="Cuerpo del correo en texto plano")
    message_id: str = Field(description="ID único del mensaje (Gmail message ID)")


class PhishingReport(BaseModel):
    resumen: str = Field(description="Resumen ejecutivo del análisis del correo")
    analisis_tecnico: str = Field(description="Evaluación técnica forense de cabeceras y contenido")
    indicadores_phishing: List[str] = Field(description="Lista de patrones de riesgo específicos contrastados con NIST/OWASP")
    es_phishing: bool = Field(description="Veredicto final de la amenaza")
    nivel_severidad: str = Field(description="Clasificación del riesgo: Bajo, Medio, Alto, Crítico")
    justificacion_veredicto: str = Field(description="Justificación académica citando controles NIST o directrices OWASP")


SCORE_UMBRAL_BAJO = 30
SCORE_UMBRAL_ALTO = 75
SCORE_FALLBACK = 50.0

SEVERIDAD_BAJO = "Bajo"
SEVERIDAD_MEDIO = "Medio"
SEVERIDAD_ALTO = "Alto"
SEVERIDAD_CRITICO = "Crítico"

TOP_K_RAG = 5
MEMORY_DATABASE = "memory-agent"
MEMORY_COLLECTION = "memory"
VECTOR_DATABASE = "phishguard"
VECTOR_COLLECTION = f"{VECTOR_DATABASE}.docs_phishing"
VECTOR_INDEX = "vector_index"
