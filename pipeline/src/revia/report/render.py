"""Renderizado del reporte auditable.

El objetivo del reporte es que la revision humana pueda reconstruir, para cada
hallazgo, la cadena completa de evidencia: que dijo la regla, que opino el modelo
y que demostro (o refuto) la PoC. Un veredicto sin esa traza es justo lo que el
proyecto busca eliminar.

Se emiten dos formatos con la misma informacion: Markdown para leer y revisar, y
JSON para que otras herramientas (o el propio CI) consuman el resultado.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import FinalStatus, PipelineReport, ReviewedFinding

_ORDEN_ESTADO = {
    FinalStatus.CONFIRMADO_EXPLOTABLE: 0,
    FinalStatus.PROBABLE_NO_VERIFICADO: 1,
    FinalStatus.REFUTADO_POR_POC: 2,
    FinalStatus.DESCARTADO_FALSO_POSITIVO: 3,
    FinalStatus.SIN_TRIAJE: 4,
}

_EMOJI = {
    FinalStatus.CONFIRMADO_EXPLOTABLE: "[CONFIRMADO]",
    FinalStatus.PROBABLE_NO_VERIFICADO: "[PROBABLE]",
    FinalStatus.REFUTADO_POR_POC: "[REFUTADO]",
    FinalStatus.DESCARTADO_FALSO_POSITIVO: "[DESCARTADO]",
    FinalStatus.SIN_TRIAJE: "[SIN TRIAJE]",
}


def _seccion_hallazgo(rf: ReviewedFinding) -> str:
    f = rf.finding
    out = [
        f"### {_EMOJI[rf.estado]} {f.titulo}",
        "",
        f"- **Hallazgo:** `{f.id}`  ·  **Regla:** `{f.rule_id}`  ·  **{f.cwe}**",
        f"- **Ubicacion:** `{f.archivo}:{f.linea}`  ·  **Severidad:** {f.severidad.value}",
        f"- **Origen:** {f.origen}  ·  **Estado final:** `{rf.estado.value}`",
        "",
        "```java",
        f.fragmento,
        "```",
        "",
    ]

    if rf.triaje:
        t = rf.triaje
        out += [
            f"**Triaje ({t.veredicto}, confianza {t.confianza:.2f}, {t.prioridad}):**",
            "",
            f"> {t.razonamiento}",
            "",
            f"- *Impacto:* {t.impacto}",
            f"- *Correccion sugerida:* {t.correccion_sugerida}",
            "",
        ]

    if rf.verificacion and rf.verificacion.intentada:
        v = rf.verificacion
        estado_poc = "CONFIRMADA" if v.explotabilidad_confirmada else "REFUTADA"
        out += [
            f"**Verificacion independiente ({estado_poc}):**",
            "",
            "```",
            v.evidencia,
            "```",
            "",
        ]
    elif rf.verificacion and rf.verificacion.motivo_omision:
        out += [f"**Verificacion:** no realizada — {rf.verificacion.motivo_omision}", ""]

    out.append("---")
    out.append("")
    return "\n".join(out)


def render_markdown(reporte: PipelineReport, evaluacion_txt: str | None = None) -> str:
    hallazgos = sorted(reporte.hallazgos, key=lambda r: (_ORDEN_ESTADO[r.estado], -r.finding.severidad.rank))

    confirmados = reporte.por_estado(FinalStatus.CONFIRMADO_EXPLOTABLE)
    probables = reporte.por_estado(FinalStatus.PROBABLE_NO_VERIFICADO)
    descartados = reporte.por_estado(FinalStatus.DESCARTADO_FALSO_POSITIVO)
    refutados = reporte.por_estado(FinalStatus.REFUTADO_POR_POC)

    out = [
        "# Reporte de revision de codigo seguro asistida por IA",
        "",
        f"- **Objetivo analizado:** `{reporte.objetivo}`",
        f"- **Generado:** {reporte.generado_en}",
        f"- **Modelo de triaje:** {reporte.modelo_triaje or 'baseline heuristico (sin IA)'}",
        f"- **Duracion:** {reporte.duracion_segundos:.1f} s"
        + (f"  ·  **Tokens:** {reporte.tokens_entrada} entrada / {reporte.tokens_salida} salida"
           if reporte.tokens_entrada else ""),
        "",
        "## Resumen",
        "",
        f"| Estado | Cantidad |",
        f"|---|---|",
        f"| Confirmado explotable (con PoC) | {len(confirmados)} |",
        f"| Probable, no verificado | {len(probables)} |",
        f"| Refutado por PoC | {len(refutados)} |",
        f"| Descartado como falso positivo | {len(descartados)} |",
        f"| **Total de hallazgos deterministas** | **{len(reporte.hallazgos)}** |",
        "",
        "> **Principio del pipeline:** ningun hallazgo se marca como confirmado sin una "
        "prueba de concepto reproducible que lo respalde. La evidencia de cada PoC se "
        "incluye integra mas abajo.",
        "",
    ]

    if evaluacion_txt:
        out += ["## Metricas contra la verdad de terreno", "", "```", evaluacion_txt, "```", ""]

    out += ["## Hallazgos en detalle", ""]
    out += [_seccion_hallazgo(rf) for rf in hallazgos]
    return "\n".join(out)


def render_json(reporte: PipelineReport) -> str:
    return reporte.model_dump_json(indent=2)


def escribir_reportes(reporte: PipelineReport, salida: Path, evaluacion_txt: str | None = None) -> tuple[Path, Path]:
    salida.mkdir(parents=True, exist_ok=True)
    md_path = salida / "reporte.md"
    json_path = salida / "reporte.json"
    md_path.write_text(render_markdown(reporte, evaluacion_txt), encoding="utf-8")
    json_path.write_text(render_json(reporte), encoding="utf-8")
    return md_path, json_path
