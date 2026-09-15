"""Contrato de datos entre las capas del pipeline.

El flujo es siempre el mismo y cada capa solo enriquece, nunca reescribe lo
anterior:

    Finding  --(triaje)-->  TriageVerdict  --(verificacion)-->  VerificationResult
       |                          |                                     |
       +--------------- ReviewedFinding (agrega los tres) --------------+

Conservar las tres piezas por separado es lo que hace auditable el veredicto:
al leer el reporte se puede reconstruir que dijo la herramienta determinista,
que opino el modelo y que demostro la prueba de concepto.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


class FinalStatus(str, Enum):
    """Estado final de un hallazgo tras recorrer el pipeline completo."""

    CONFIRMADO_EXPLOTABLE = "CONFIRMADO_EXPLOTABLE"
    """Hay una PoC reproducible que lo demuestra. Unico estado con evidencia dura."""

    PROBABLE_NO_VERIFICADO = "PROBABLE_NO_VERIFICADO"
    """El triaje lo considera real pero no se pudo (o no aplica) verificar dinamicamente."""

    DESCARTADO_FALSO_POSITIVO = "DESCARTADO_FALSO_POSITIVO"
    """El triaje lo descarto con justificacion."""

    REFUTADO_POR_POC = "REFUTADO_POR_POC"
    """El triaje lo creia real y la PoC demostro que NO es explotable."""

    SIN_TRIAJE = "SIN_TRIAJE"
    """Salio de la capa determinista y no paso por el triaje (modo --solo-sast)."""


class Finding(BaseModel):
    """Hallazgo candidato producido por la capa determinista."""

    id: str
    rule_id: str
    titulo: str
    cwe: str
    severidad: Severity
    archivo: str
    linea: int
    fragmento: str
    mensaje: str
    origen: Literal["sast-builtin", "semgrep", "sca"]
    ruido_esperado: Literal["bajo", "medio", "alto"] = "medio"
    """Expectativa a priori de la regla. Se le pasa al triaje como contexto, no como veredicto."""


class TriageVerdict(BaseModel):
    """Salida estructurada del modelo. Es una HIPOTESIS, nunca un veredicto final."""

    veredicto: Literal["verdadero_positivo", "falso_positivo", "incierto"] = Field(
        description="Si el hallazgo describe un defecto real en este codigo concreto."
    )
    confianza: float = Field(ge=0.0, le=1.0, description="Confianza en el veredicto, de 0 a 1.")
    razonamiento: str = Field(
        description="Por que. Debe citar el codigo concreto, no repetir la descripcion de la regla."
    )
    impacto: str = Field(description="Que gana un atacante si el hallazgo es real.")
    verificable_dinamicamente: bool = Field(
        description="Si se puede demostrar con una peticion HTTP contra el servicio en ejecucion."
    )
    estrategia_poc: str = Field(
        description="Pasos concretos para demostrarlo: rutas, cabeceras, credenciales y senal de exito."
    )
    correccion_sugerida: str = Field(description="El cambio minimo que cierra el hallazgo.")
    prioridad: Literal["P0", "P1", "P2", "P3"] = Field(description="P0 es lo mas urgente.")


class VerificationResult(BaseModel):
    """Evidencia independiente. Es lo unico que puede ascender un hallazgo a CONFIRMADO."""

    intentada: bool
    explotabilidad_confirmada: bool
    poc_ruta: str | None = None
    codigo_salida: int | None = None
    evidencia: str = ""
    motivo_omision: str | None = None


class ReviewedFinding(BaseModel):
    """Un hallazgo con toda su trazabilidad: regla, hipotesis del modelo y prueba."""

    finding: Finding
    triaje: TriageVerdict | None = None
    verificacion: VerificationResult | None = None
    estado: FinalStatus = FinalStatus.SIN_TRIAJE

    def resolver_estado(self) -> FinalStatus:
        """Aplica el principio del pipeline: ningun veredicto sin evidencia que lo respalde.

        La PoC manda sobre el modelo en ambas direcciones. Si la prueba confirma,
        el hallazgo asciende aunque el triaje dudara; si la prueba refuta, cae
        aunque el triaje estuviera seguro.
        """
        if self.triaje is None:
            self.estado = FinalStatus.SIN_TRIAJE
            return self.estado

        if self.verificacion and self.verificacion.intentada:
            self.estado = (
                FinalStatus.CONFIRMADO_EXPLOTABLE
                if self.verificacion.explotabilidad_confirmada
                else FinalStatus.REFUTADO_POR_POC
            )
            return self.estado

        self.estado = (
            FinalStatus.DESCARTADO_FALSO_POSITIVO
            if self.triaje.veredicto == "falso_positivo"
            else FinalStatus.PROBABLE_NO_VERIFICADO
        )
        return self.estado

    @property
    def reportable(self) -> bool:
        """Lo que llega a la revision humana: todo menos lo descartado o refutado."""
        return self.estado not in (
            FinalStatus.DESCARTADO_FALSO_POSITIVO,
            FinalStatus.REFUTADO_POR_POC,
        )


class PipelineReport(BaseModel):
    objetivo: str
    generado_en: str
    modelo_triaje: str | None
    hallazgos: list[ReviewedFinding]
    duracion_segundos: float = 0.0
    tokens_entrada: int = 0
    tokens_salida: int = 0

    def por_estado(self, estado: FinalStatus) -> list[ReviewedFinding]:
        return [h for h in self.hallazgos if h.estado == estado]
