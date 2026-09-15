"""Orquestador del pipeline. Une las tres capas y produce el reporte auditable.

    determinista  ->  triaje (LLM)  ->  verificacion (PoC)  ->  reporte + metricas

Cada capa consume la salida de la anterior y solo agrega informacion. El estado
final de cada hallazgo lo resuelve `ReviewedFinding.resolver_estado`, que aplica
la regla central: la PoC manda sobre la opinion del modelo.

Uso tipico:

    python -m revia.pipeline --objetivo ../target --con-verificacion
    python -m revia.pipeline --objetivo ../target --sin-ia          # baseline
    python -m revia.pipeline --objetivo ../target --evaluar         # + metricas
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
import time
from pathlib import Path

from .evaluation.metrics import GroundTruth, evaluar, formatear
from .layers.deterministic import run_deterministic_layer
from .layers.triage import MODELO_POR_DEFECTO, run_triage_layer
from .layers.verification import ObjetivoEjecucion, run_verification_layer
from .models import PipelineReport, ReviewedFinding
from .report.render import escribir_reportes

# Credenciales del banco de pruebas. Se usan solo para las PoC contra el objetivo
# local; representan "atacante" y el recurso de la "victima" que no le pertenece.
OBJETIVO_PRUEBA = {
    "atacante": "token-ana",          # Ana, usuaria legitima
    "recurso_victima": "ord-9",       # pedido cuyo propietario es Bruno
    "marcador_victima": "u-2002",     # id de Bruno: senal de exfiltracion
    "recurso_victima_interno": "u-2002",
}


def ejecutar(
    objetivo: Path,
    rules_path: Path,
    salida: Path,
    usar_ia: bool,
    con_verificacion: bool,
    base_url: str,
    modelo: str,
    usar_semgrep: bool,
    dataset: Path | None,
) -> PipelineReport:
    inicio = time.perf_counter()
    generado = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # -- Capa 1: determinista --------------------------------------------------
    print(f"\n== Capa determinista sobre {objetivo} ==")
    findings = run_deterministic_layer(objetivo, rules_path, usar_semgrep=usar_semgrep)
    print(f"   {len(findings)} hallazgos candidatos")

    # -- Capa 2: triaje --------------------------------------------------------
    print("\n== Capa de triaje ==")
    triajes, uso = run_triage_layer(findings, objetivo, modelo=modelo, usar_ia=usar_ia)

    # -- Capa 3: verificacion --------------------------------------------------
    verificaciones: dict = {}
    if con_verificacion:
        print("\n== Capa de verificacion ==")
        objetivo_run = ObjetivoEjecucion(base_url=base_url, tokens_prueba=OBJETIVO_PRUEBA)
        if not objetivo_run.disponible:
            print(f"   Objetivo {base_url} no responde. Se omiten las PoC.")
            objetivo_run = None  # type: ignore[assignment]
        verificaciones = run_verification_layer(findings, triajes, objetivo_run)

    # -- Ensamblado ------------------------------------------------------------
    revisados: list[ReviewedFinding] = []
    for f in findings:
        rf = ReviewedFinding(
            finding=f,
            triaje=triajes.get(f.id),
            verificacion=verificaciones.get(f.id),
        )
        rf.resolver_estado()
        revisados.append(rf)

    reporte = PipelineReport(
        objetivo=str(objetivo),
        generado_en=generado,
        modelo_triaje=modelo if usar_ia else None,
        hallazgos=revisados,
        duracion_segundos=time.perf_counter() - inicio,
        tokens_entrada=uso.entrada,
        tokens_salida=uso.salida,
    )

    # -- Metricas --------------------------------------------------------------
    evaluacion_txt = None
    if dataset is not None:
        gt = GroundTruth(dataset)
        evaluacion_txt = formatear(evaluar(revisados, gt))
        print("\n" + evaluacion_txt)

    md_path, json_path = escribir_reportes(reporte, salida, evaluacion_txt)
    print(f"\nReporte: {md_path}")
    print(f"JSON:    {json_path}")
    return reporte


def main(argv: list[str] | None = None) -> int:
    aqui = Path(__file__).resolve()
    repo = aqui.parents[3]  # .../seminario-codigo-seguro-ia

    parser = argparse.ArgumentParser(description="Pipeline de revision de codigo seguro con verificacion independiente")
    parser.add_argument("--objetivo", type=Path, default=repo / "target", help="Raiz del codigo a analizar")
    parser.add_argument("--reglas", type=Path, default=repo / "pipeline" / "rules" / "java-spring.yml")
    parser.add_argument("--salida", type=Path, default=repo / "out")
    parser.add_argument("--dataset", type=Path, default=repo / "dataset" / "ground-truth.yml")
    parser.add_argument("--modelo", default=MODELO_POR_DEFECTO)
    parser.add_argument("--base-url", default="http://127.0.0.1:8081", help="URL del objetivo vivo para las PoC")
    parser.add_argument("--sin-ia", action="store_true", help="Usa el baseline heuristico en vez del modelo")
    parser.add_argument("--con-verificacion", action="store_true", help="Ejecuta las PoC contra el objetivo vivo")
    parser.add_argument("--con-semgrep", action="store_true", help="Suma Semgrep si esta instalado")
    parser.add_argument("--evaluar", action="store_true", help="Calcula metricas contra el dataset etiquetado")
    args = parser.parse_args(argv)

    ejecutar(
        objetivo=args.objetivo,
        rules_path=args.reglas,
        salida=args.salida,
        usar_ia=not args.sin_ia,
        con_verificacion=args.con_verificacion,
        base_url=args.base_url,
        modelo=args.modelo,
        usar_semgrep=args.con_semgrep,
        dataset=args.dataset if args.evaluar else None,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
