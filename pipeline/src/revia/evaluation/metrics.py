"""Metricas de evaluacion contra la verdad de terreno.

Responde la pregunta de investigacion con numeros: un pipeline con verificacion
independiente, reduce los falsos positivos y confirma explotabilidad sin
sacrificar cobertura? Para responderla se comparan dos configuraciones sobre el
MISMO conjunto de hallazgos:

  * "SAST solo": todo hallazgo de la capa determinista cuenta como positivo. Es
    el comportamiento sin triaje ni verificacion.
  * "Pipeline": positivo = lo que sobrevive al triaje (no descartado como falso
    positivo). Es el sistema propuesto.

Sobre cada configuracion se calculan precision, recall y F1 contra las etiquetas
humanas, ademas de la tasa de falsos positivos antes/despues y el porcentaje de
hallazgos con explotabilidad confirmada por PoC.

Advertencia metodologica honesta: el dataset del prototipo es pequeno (un banco
de pruebas), asi que estas cifras ilustran el metodo, no lo validan
estadisticamente. Ampliar el dataset es trabajo de la fase siguiente.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..models import FinalStatus, ReviewedFinding


@dataclass(frozen=True)
class Etiqueta:
    rule_id: str
    archivo: str
    etiqueta: str  # verdadero_positivo | falso_positivo
    explotable: bool
    cwe: str
    nota: str

    @property
    def es_tp(self) -> bool:
        return self.etiqueta == "verdadero_positivo"


class GroundTruth:
    def __init__(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        self._por_clave: dict[tuple[str, str], Etiqueta] = {}
        for e in data["entradas"]:
            etiqueta = Etiqueta(
                rule_id=e["rule_id"],
                archivo=e["archivo"],
                etiqueta=e["etiqueta"],
                explotable=bool(e.get("explotable", False)),
                cwe=e.get("cwe", "CWE-desconocido"),
                nota=e.get("nota", ""),
            )
            self._por_clave[(etiqueta.rule_id, etiqueta.archivo)] = etiqueta

    def lookup(self, rule_id: str, archivo: str) -> Etiqueta | None:
        return self._por_clave.get((rule_id, archivo))

    @property
    def total_tp(self) -> int:
        return sum(1 for e in self._por_clave.values() if e.es_tp)


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def tasa_fp(self) -> float:
        """Proporcion de positivos emitidos que en realidad eran falsos."""
        emitidos = self.tp + self.fp
        return self.fp / emitidos if emitidos else 0.0


@dataclass
class Evaluacion:
    sast_solo: Confusion = field(default_factory=Confusion)
    pipeline: Confusion = field(default_factory=Confusion)
    confirmados_por_poc: int = 0
    tp_explotables_totales: int = 0
    sin_etiqueta: list[str] = field(default_factory=list)

    @property
    def reduccion_fp(self) -> int:
        return self.sast_solo.fp - self.pipeline.fp

    @property
    def pct_explotabilidad_confirmada(self) -> float:
        if not self.tp_explotables_totales:
            return 0.0
        return 100.0 * self.confirmados_por_poc / self.tp_explotables_totales


def evaluar(revisados: list[ReviewedFinding], gt: GroundTruth) -> Evaluacion:
    ev = Evaluacion(tp_explotables_totales=sum(
        1 for e in gt._por_clave.values() if e.es_tp and e.explotable
    ))

    for rf in revisados:
        etiqueta = gt.lookup(rf.finding.rule_id, rf.finding.archivo)
        if etiqueta is None:
            ev.sin_etiqueta.append(f"{rf.finding.rule_id} @ {rf.finding.archivo}")
            continue

        real_positivo = etiqueta.es_tp

        # --- SAST solo: cada hallazgo determinista es un positivo emitido ---
        if real_positivo:
            ev.sast_solo.tp += 1
        else:
            ev.sast_solo.fp += 1

        # --- Pipeline: positivo = no descartado por el triaje ---
        emitido_pipeline = rf.estado != FinalStatus.DESCARTADO_FALSO_POSITIVO
        if emitido_pipeline and real_positivo:
            ev.pipeline.tp += 1
        elif emitido_pipeline and not real_positivo:
            ev.pipeline.fp += 1
        elif not emitido_pipeline and real_positivo:
            ev.pipeline.fn += 1  # el triaje descarto un hallazgo real: coste de cobertura
        else:
            ev.pipeline.tn += 1  # descarto correctamente un falso positivo

        # --- Explotabilidad confirmada ---
        if rf.estado == FinalStatus.CONFIRMADO_EXPLOTABLE:
            ev.confirmados_por_poc += 1

    return ev


def formatear(ev: Evaluacion) -> str:
    def bloque(nombre: str, c: Confusion) -> str:
        return (
            f"  {nombre}\n"
            f"    TP={c.tp}  FP={c.fp}  FN={c.fn}  TN={c.tn}\n"
            f"    precision={c.precision:.2f}  recall={c.recall:.2f}  "
            f"F1={c.f1:.2f}  tasa_FP={c.tasa_fp:.2f}"
        )

    lineas = [
        "METRICAS DE EVALUACION",
        "=" * 60,
        bloque("SAST solo (sin triaje ni verificacion)", ev.sast_solo),
        bloque("Pipeline (con triaje + verificacion)", ev.pipeline),
        "-" * 60,
        f"  Reduccion de falsos positivos: {ev.reduccion_fp} "
        f"({ev.sast_solo.fp} -> {ev.pipeline.fp})",
        f"  Explotabilidad confirmada por PoC: {ev.confirmados_por_poc}/"
        f"{ev.tp_explotables_totales} ({ev.pct_explotabilidad_confirmada:.0f}%)",
    ]
    if ev.sin_etiqueta:
        lineas.append(f"  Hallazgos sin etiqueta en el dataset: {len(ev.sin_etiqueta)}")
    return "\n".join(lineas)
