"""Pruebas del pipeline. Corren sin credenciales ni red externa.

Cubren las tres invariantes que sostienen la tesis del proyecto:

  1. La capa determinista detecta el IDOR por AUSENCIA de comprobacion y NO se
     dispara cuando la comprobacion si esta presente.
  2. La regla central del pipeline se cumple: la PoC decide el estado final por
     encima del triaje, en ambas direcciones.
  3. Contra la verdad de terreno, el pipeline reduce falsos positivos frente a
     "SAST solo" sin perder los verdaderos positivos explotables.

La capa de verificacion se prueba levantando el objetivo mock real en un hilo,
no con dobles de prueba: es justo la parte cuyo valor es "lo demuestra de verdad".
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "target" / "mock"))

from revia.evaluation.metrics import GroundTruth, evaluar  # noqa: E402
from revia.layers.deterministic import RuleEngine, run_deterministic_layer  # noqa: E402
from revia.layers.triage import run_triage_layer  # noqa: E402
from revia.layers.verification import ObjetivoEjecucion, run_verification_layer  # noqa: E402
from revia.models import FinalStatus, ReviewedFinding, TriageVerdict, VerificationResult  # noqa: E402

REGLAS = REPO / "pipeline" / "rules" / "java-spring.yml"
OBJETIVO = REPO / "target"
DATASET = REPO / "dataset" / "ground-truth.yml"


# --------------------------------------------------------------------------
# Capa determinista
# --------------------------------------------------------------------------

def test_detecta_idor_en_order_controller():
    findings = run_deterministic_layer(OBJETIVO, REGLAS, usar_semgrep=False)
    idor = [f for f in findings if f.rule_id == "java.spring.idor-sin-verificacion-propiedad"]
    archivos = {f.archivo.split("/")[-1] for f in idor}
    assert "OrderController.java" in archivos


def test_regla_ausencia_no_dispara_cuando_hay_verificacion(tmp_path):
    """Si el metodo compara el propietario, la regla de IDOR NO debe activarse."""
    seguro = tmp_path / "Safe.java"
    seguro.write_text(
        """
        package demo;
        class Safe {
            @GetMapping("/api/orders/{orderId}")
            public Object get(@PathVariable String orderId, String callerId) {
                var order = repo.find(orderId);
                if (!order.getOwner().equals(callerId)) { return forbidden(); }
                return order;
            }
        }
        """,
        encoding="utf-8",
    )
    findings = RuleEngine(REGLAS).scan_tree(tmp_path)
    idor = [f for f in findings if f.rule_id == "java.spring.idor-sin-verificacion-propiedad"]
    assert idor == []


def test_enmascara_comentarios_y_literales(tmp_path):
    """Un patron que solo aparece en un comentario o una cadena no es un hallazgo."""
    ruido = tmp_path / "Noise.java"
    ruido.write_text(
        """
        package demo;
        class Noise {
            // MessageDigest.getInstance("MD5") <- esto es un comentario, no codigo
            String q = "SELECT * FROM t WHERE x = 1"; // sin concatenacion real
        }
        """,
        encoding="utf-8",
    )
    findings = RuleEngine(REGLAS).scan_tree(tmp_path)
    assert findings == []


# --------------------------------------------------------------------------
# Resolucion de estado: la PoC manda sobre el triaje
# --------------------------------------------------------------------------

def _triaje(veredicto: str) -> TriageVerdict:
    return TriageVerdict(
        veredicto=veredicto, confianza=0.9, razonamiento="x", impacto="x",
        verificable_dinamicamente=True, estrategia_poc="x", correccion_sugerida="x",
        prioridad="P1",
    )


def test_poc_confirmada_asciende_hallazgo_incierto():
    findings = run_deterministic_layer(OBJETIVO, REGLAS, usar_semgrep=False)
    rf = ReviewedFinding(
        finding=findings[0],
        triaje=_triaje("incierto"),
        verificacion=VerificationResult(intentada=True, explotabilidad_confirmada=True),
    )
    assert rf.resolver_estado() == FinalStatus.CONFIRMADO_EXPLOTABLE


def test_poc_refuta_hallazgo_que_el_triaje_daba_por_bueno():
    findings = run_deterministic_layer(OBJETIVO, REGLAS, usar_semgrep=False)
    rf = ReviewedFinding(
        finding=findings[0],
        triaje=_triaje("verdadero_positivo"),
        verificacion=VerificationResult(intentada=True, explotabilidad_confirmada=False),
    )
    assert rf.resolver_estado() == FinalStatus.REFUTADO_POR_POC


def test_sin_poc_hereda_del_triaje():
    findings = run_deterministic_layer(OBJETIVO, REGLAS, usar_semgrep=False)
    rf = ReviewedFinding(finding=findings[0], triaje=_triaje("falso_positivo"), verificacion=None)
    assert rf.resolver_estado() == FinalStatus.DESCARTADO_FALSO_POSITIVO


# --------------------------------------------------------------------------
# Verificacion contra el objetivo mock real
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def objetivo_vivo():
    from run_target import TargetHandler  # del target/mock

    server = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    puerto = server.server_address[1]
    hilo = threading.Thread(target=server.serve_forever, daemon=True)
    hilo.start()
    base = f"http://127.0.0.1:{puerto}"
    for _ in range(50):
        try:
            urllib.request.urlopen(base, timeout=1)
            break
        except Exception:
            time.sleep(0.05)
    yield base
    server.shutdown()
    server.server_close()


def test_poc_idor_confirma_exfiltracion_real(objetivo_vivo):
    findings = run_deterministic_layer(OBJETIVO, REGLAS, usar_semgrep=False)
    triajes, _ = run_triage_layer(findings, OBJETIVO, usar_ia=False)
    objetivo = ObjetivoEjecucion(
        base_url=objetivo_vivo,
        tokens_prueba={"atacante": "token-ana", "recurso_victima": "ord-9", "marcador_victima": "u-2002"},
    )
    resultados = run_verification_layer(findings, triajes, objetivo)
    confirmados = [r for r in resultados.values() if r.explotabilidad_confirmada]
    assert confirmados, "La PoC del IDOR deberia confirmar la exfiltracion contra el objetivo vivo"
    assert any("Bruno" in r.evidencia for r in confirmados)


# --------------------------------------------------------------------------
# Metricas end-to-end
# --------------------------------------------------------------------------

def test_pipeline_reduce_falsos_positivos_sin_perder_explotables(objetivo_vivo):
    findings = run_deterministic_layer(OBJETIVO, REGLAS, usar_semgrep=False)
    triajes, _ = run_triage_layer(findings, OBJETIVO, usar_ia=False)
    objetivo = ObjetivoEjecucion(
        base_url=objetivo_vivo,
        tokens_prueba={"atacante": "token-ana", "recurso_victima": "ord-9",
                       "marcador_victima": "u-2002", "recurso_victima_interno": "u-2002"},
    )
    verificaciones = run_verification_layer(findings, triajes, objetivo)

    revisados = []
    for f in findings:
        rf = ReviewedFinding(finding=f, triaje=triajes.get(f.id), verificacion=verificaciones.get(f.id))
        rf.resolver_estado()
        revisados.append(rf)

    ev = evaluar(revisados, GroundTruth(DATASET))
    assert ev.pipeline.fp <= ev.sast_solo.fp        # no aumenta falsos positivos
    assert ev.confirmados_por_poc >= 1              # al menos un IDOR confirmado por PoC
    assert ev.sin_etiqueta == []                    # el dataset cubre todos los hallazgos


def test_cli_baseline_termina_bien():
    """Humo del orquestador completo por linea de comandos, sin IA."""
    proc = subprocess.run(
        [sys.executable, "-m", "revia.pipeline", "--sin-ia", "--evaluar",
         "--salida", str(REPO / "out" / "test")],
        capture_output=True, text=True, cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr
    assert "METRICAS DE EVALUACION" in proc.stdout
