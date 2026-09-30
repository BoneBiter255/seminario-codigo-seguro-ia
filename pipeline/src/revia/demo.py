"""Demostracion guiada de extremo a extremo: despliega el banco de pruebas y
recorre cada componente del pipeline, uno por paso.

    0. Despliegue del banco de pruebas vulnerable (order-service + user-service)
    1. El ataque en vivo: IDOR cross-service y cabecera interna falsificable
    2. Capa determinista: lo que ve el SAST solo
    3. Capa de triaje: baseline sin IA  vs  LLM gratuito leyendo el codigo
    4. Capa de verificacion: PoC reales contra el servicio en ejecucion
    5. Metricas contra la verdad de terreno: SAST solo / baseline / LLM
    6. Reporte auditable

Uso:

    python -m revia.demo                         # proveedor LLM automatico
    python -m revia.demo --proveedor ollama      # forzar un proveedor
    python -m revia.demo --sin-pausas            # sin esperar Enter entre pasos
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from .evaluation.metrics import Confusion, GroundTruth, evaluar
from .layers.deterministic import run_deterministic_layer
from .layers.triage import PROVEEDORES, run_triage_layer
from .layers.verification import ObjetivoEjecucion, run_verification_layer
from .models import FinalStatus, PipelineReport, ReviewedFinding
from .report.render import escribir_reportes

REPO = Path(__file__).resolve().parents[3]
OBJETIVO = REPO / "target"
REGLAS = REPO / "pipeline" / "rules" / "java-spring.yml"
DATASET = REPO / "dataset" / "ground-truth.yml"

ANCHO = 72


def titulo(paso: str, texto: str) -> None:
    print("\n" + "=" * ANCHO)
    print(f"  {paso}  {texto}")
    print("=" * ANCHO)


def pausa(activa: bool) -> None:
    if activa:
        try:
            input("\n  [Enter para continuar] ")
        except EOFError:
            pass


def _puerto_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str, headers: dict[str, str]) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, ""


def _mostrar_peticion(descripcion: str, url: str, headers: dict[str, str]) -> None:
    cab = "  ".join(f"{k}: {v}" for k, v in headers.items())
    print(f"\n  > {descripcion}")
    print(f"    GET {url}   [{cab}]")
    status, cuerpo = _get(url, headers)
    try:
        cuerpo = json.dumps(json.loads(cuerpo), ensure_ascii=False, indent=2)
    except ValueError:
        pass
    print(f"    <- HTTP {status}")
    for linea in cuerpo.splitlines():
        print(f"       {linea}")


def desplegar_banco(puerto: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(OBJETIVO / "mock" / "run_target.py"), "--port", str(puerto)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{puerto}"
    for _ in range(50):
        if proc.poll() is not None:
            raise RuntimeError("El banco de pruebas no pudo arrancar")
        try:
            _get(base + "/api/orders", {"Authorization": "Bearer token-ana"})
            return proc
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("El banco de pruebas no respondio a tiempo")


def ensamblar(findings, triajes, verificaciones) -> list[ReviewedFinding]:
    revisados = []
    for f in findings:
        rf = ReviewedFinding(finding=f, triaje=triajes.get(f.id), verificacion=verificaciones.get(f.id))
        rf.resolver_estado()
        revisados.append(rf)
    return revisados


def fila(nombre: str, c: Confusion) -> str:
    return f"  {nombre:<30} {c.precision:>9.2f} {c.recall:>7.2f} {c.f1:>6.2f} {c.fp:>5}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Demostracion guiada del pipeline REVIA")
    parser.add_argument("--proveedor", default="auto", choices=PROVEEDORES)
    parser.add_argument("--modelo", default=None)
    parser.add_argument("--sin-pausas", action="store_true")
    parser.add_argument("--salida", type=Path, default=REPO / "out")
    args = parser.parse_args(argv)
    pausas = not args.sin_pausas

    # ------------------------------------------------------------------ 0
    titulo("PASO 0", "Despliegue del banco de pruebas vulnerable")
    puerto = _puerto_libre()
    banco = desplegar_banco(puerto)
    base = f"http://127.0.0.1:{puerto}"
    print(f"  order-service + user-service escuchando en {base}")
    print("  (replica solo-Python de los microservicios Spring de target/)")

    try:
        # -------------------------------------------------------------- 1
        titulo("PASO 1", "El ataque en vivo")
        _mostrar_peticion("Ana pide SUS pedidos (legitimo)", f"{base}/api/orders",
                          {"Authorization": "Bearer token-ana"})
        _mostrar_peticion("Ana pide el pedido ord-9, que es de Bruno (IDOR)", f"{base}/api/orders/ord-9",
                          {"Authorization": "Bearer token-ana"})
        _mostrar_peticion("Sin token, falsificando la cabecera interna", f"{base}/internal/users/u-2002",
                          {"X-Internal-Call": "true"})
        print("\n  Ana obtiene nombre, documento y telefono de Bruno. Y cualquiera puede")
        print("  leer user-service solo con escribir la cabecera X-Internal-Call.")
        pausa(pausas)

        # -------------------------------------------------------------- 2
        titulo("PASO 2", "Capa 1 - analisis determinista (SAST)")
        findings = run_deterministic_layer(OBJETIVO, REGLAS, usar_semgrep=False)
        gt = GroundTruth(DATASET)
        print(f"  {len(findings)} hallazgos candidatos:\n")
        for f in findings:
            e = gt.lookup(f.rule_id, f.archivo)
            real = "REAL " if e and e.es_tp else "RUIDO"
            print(f"   [{real}] {f.cwe:<8} {f.rule_id:<45} {Path(f.archivo).name}:{f.linea}")
        print("\n  La etiqueta REAL/RUIDO viene del dataset humano; el SAST no la conoce.")
        print("  El SAST sobre-reporta a proposito: prefiere no perder nada.")
        pausa(pausas)

        # -------------------------------------------------------------- 3
        titulo("PASO 3", "Capa 2 - triaje")
        print("  3a) Baseline SIN IA (grupo de control: solo mira el 'ruido' de la regla)\n")
        tri_base, _, _ = run_triage_layer(findings, OBJETIVO, usar_ia=False)

        print("\n  3b) LLM gratuito leyendo el codigo real de cada hallazgo\n")
        tri_llm, uso, etiqueta_llm = run_triage_layer(
            findings, OBJETIVO, modelo=args.modelo, proveedor=args.proveedor, usar_ia=True
        )
        hubo_llm = etiqueta_llm != "baseline-heuristico"
        if not hubo_llm:
            print("\n  No hay LLM disponible: arranca Ollama (`ollama serve`) o define")
            print("  GEMINI_API_KEY / GROQ_API_KEY. La demo sigue solo con el baseline.")

        print(f"\n  {'Hallazgo':<45} {'Baseline':<20} {'LLM':<20}")
        for f in findings:
            vl = tri_llm[f.id].veredicto if hubo_llm else "-"
            print(f"  {f.rule_id:<45} {tri_base[f.id].veredicto:<20} {vl:<20}")
        pausa(pausas)

        # -------------------------------------------------------------- 4
        titulo("PASO 4", "Capa 3 - verificacion independiente (PoC reales)")
        tri_final = tri_llm if hubo_llm else tri_base
        objetivo_run = ObjetivoEjecucion(
            base_url=base,
            tokens_prueba={"atacante": "token-ana", "recurso_victima": "ord-9",
                           "marcador_victima": "u-2002", "recurso_victima_interno": "u-2002"},
        )
        verif = run_verification_layer(findings, tri_final, objetivo_run)
        for f in findings:
            v = verif.get(f.id)
            if v and v.intentada:
                marca = "CONFIRMADO" if v.explotabilidad_confirmada else "REFUTADO"
                print(f"\n  [{marca}] {f.rule_id}")
                print(f"    PoC: {v.poc_ruta}")
                print("    Evidencia:")
                for linea in v.evidencia.strip().splitlines()[:6]:
                    print(f"      {linea.strip()[:100]}")
        print("\n  La PoC manda sobre la opinion del modelo, en las dos direcciones.")
        pausa(pausas)

        # -------------------------------------------------------------- 5
        titulo("PASO 5", "Metricas contra la verdad de terreno (dataset/ground-truth.yml)")
        ev_base = evaluar(ensamblar(findings, tri_base, verif), gt)
        print(f"  {'Configuracion':<30} {'Precision':>9} {'Recall':>7} {'F1':>6} {'FP':>5}")
        print(fila("SAST solo", ev_base.sast_solo))
        print(fila("Pipeline + baseline sin IA", ev_base.pipeline))
        revisados = ensamblar(findings, tri_final, verif)
        if hubo_llm:
            ev_llm = evaluar(revisados, gt)
            print(fila(f"Pipeline + LLM ({etiqueta_llm.split(' ')[0]})", ev_llm.pipeline))
            ok = ev_llm.pipeline.f1 >= 0.80
            print(f"\n  Objetivo F1 >= 0.80 con LLM gratuito: {'CUMPLIDO' if ok else 'NO cumplido'} "
                  f"(F1 = {ev_llm.pipeline.f1:.2f})")
            if "degradados" in etiqueta_llm:
                print(f"  ATENCION: {etiqueta_llm} -- parte del resultado no vino del LLM.")
        confirmados = sum(1 for r in revisados if r.estado == FinalStatus.CONFIRMADO_EXPLOTABLE)
        print(f"\n  Explotabilidad confirmada por PoC: {confirmados}/{ev_base.tp_explotables_totales}")
        print("  Dataset pequeno (un banco de pruebas): ilustra el metodo, no lo valida.")
        pausa(pausas)

        # -------------------------------------------------------------- 6
        titulo("PASO 6", "Reporte auditable")
        reporte = PipelineReport(
            objetivo=str(OBJETIVO),
            generado_en=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            modelo_triaje=etiqueta_llm if hubo_llm else None,
            hallazgos=revisados,
            tokens_entrada=uso.entrada,
            tokens_salida=uso.salida,
        )
        md, js = escribir_reportes(reporte, args.salida)
        print(f"  {md}\n  {js}")
        print("  Cada hallazgo guarda lo que dijo la regla, lo que opino el modelo")
        print("  y lo que demostro la PoC, por separado.")
    finally:
        banco.terminate()
        print("\n  Banco de pruebas detenido.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
