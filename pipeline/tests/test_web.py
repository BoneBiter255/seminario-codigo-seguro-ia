"""Pruebas de los escenarios, del motor con eventos y de la API web.

Corren sin LLM: usan el baseline sin IA y los bancos reales en hilos.
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "target" / "mock"))

from revia import motor  # noqa: E402
from revia.escenarios import ESCENARIOS, REGLAS  # noqa: E402
from revia.layers.deterministic import run_deterministic_layer  # noqa: E402
from run_target import arrancar_en_hilo  # noqa: E402


@pytest.fixture(scope="module")
def bancos():
    srv_v, url_v = arrancar_en_hilo("vulnerable")
    srv_c, url_c = arrancar_en_hilo("corregido")
    yield {"vulnerable": url_v, "corregido": url_c}
    for s in (srv_v, srv_c):
        s.shutdown()
        s.server_close()


@pytest.fixture
def salida_temporal(tmp_path, monkeypatch):
    monkeypatch.setattr(motor, "SALIDA_WEB", tmp_path)
    return tmp_path


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, ""


# --------------------------------------------------------------------------
# Escenarios
# --------------------------------------------------------------------------

def test_corregido_solo_difiere_en_el_fix():
    """El grupo de control debe ser el mismo codigo salvo el fix, para aislar su efecto."""
    a, b = ESCENARIOS["vulnerable"].raiz, ESCENARIOS["corregido"].raiz
    distintos = set()
    for p in a.rglob("*"):
        if p.is_file() and "mock" not in p.parts:
            rel = p.relative_to(a)
            otro = b / rel
            if not otro.exists() or otro.read_bytes() != p.read_bytes():
                distintos.add(rel.as_posix())
    assert distintos == {
        "order-service/src/main/java/com/seminario/order/OrderController.java",
        "user-service/src/main/java/com/seminario/user/InternalUserController.java",
        "user-service/src/main/resources/application.yml",
    }


def test_fix_elimina_los_hallazgos_de_la_cadena():
    hallazgos = run_deterministic_layer(ESCENARIOS["corregido"].raiz, REGLAS, usar_semgrep=False)
    claves = {(h.rule_id, h.archivo.rsplit("/", 1)[-1]) for h in hallazgos}
    assert ("java.spring.idor-sin-verificacion-propiedad", "OrderController.java") not in claves
    assert ("java.spring.confianza-en-cabecera-interna", "InternalUserController.java") not in claves


def test_codigo_del_banco_no_revela_la_respuesta():
    """El LLM no debe recibir etiquetas como 'VULNERABILIDAD (CWE-...)' en el codigo."""
    for esc in ESCENARIOS.values():
        for p in esc.raiz.rglob("*.java"):
            texto = p.read_text(encoding="utf-8")
            assert "VULNERABILIDAD" not in texto, p
            assert "CWE-" not in texto, p


@pytest.mark.parametrize("modo,ruta,headers,esperado", [
    ("vulnerable", "/api/orders/ord-9", {"Authorization": "Bearer token-ana"}, 200),
    ("corregido", "/api/orders/ord-9", {"Authorization": "Bearer token-ana"}, 403),
    ("corregido", "/api/orders/ord-1", {"Authorization": "Bearer token-ana"}, 200),
    ("corregido", "/internal/users/u-2002", {"X-Internal-Call": "true"}, 403),
])
def test_modos_del_banco(bancos, modo, ruta, headers, esperado):
    estado, _ = _get(bancos[modo] + ruta, headers)
    assert estado == esperado


# --------------------------------------------------------------------------
# Motor
# --------------------------------------------------------------------------

def test_motor_vulnerable_confirma_y_valida_fixes(bancos, salida_temporal):
    eventos = []
    r = motor.ejecutar(
        motor.ConfigEjecucion(escenario="vulnerable", modo="baseline",
                              base_url=bancos["vulnerable"], base_url_corregido=bancos["corregido"]),
        eventos.append,
    )
    m = r["metricas"]
    assert m["confirmados_poc"] == 3
    assert m["falsas_confirmaciones"] == 0
    assert m["explotabilidad_pct"] == 100.0
    assert m["fixes_validados_pct"] == 100.0
    assert m["sin_etiqueta"] == []
    tipos = [e["tipo"] for e in eventos]
    assert tipos[0] == "inicio" and tipos[-1] == "fin"
    assert tipos.count("hallazgo") == tipos.count("triaje_fin") == len(r["comparacion"])
    assert (salida_temporal / r["id"] / "resultado.json").exists()
    assert (salida_temporal / r["id"] / "reporte.md").exists()


def test_motor_control_no_confirma_nada(bancos, salida_temporal):
    r = motor.ejecutar(motor.ConfigEjecucion(escenario="corregido", modo="baseline",
                                             base_url=bancos["corregido"]))
    assert r["metricas"]["confirmados_poc"] == 0
    crit = {c["id"]: c for c in r["criterios"]}
    assert crit["falsas_confirmaciones"]["cumple"] is True


def test_poc_no_respalda_hallazgos_de_otro_endpoint(bancos, salida_temporal):
    """El IDOR del catalogo publico de plantillas no puede 'confirmarse' con la PoC de pedidos."""
    r = motor.ejecutar(motor.ConfigEjecucion(escenario="vulnerable", modo="baseline",
                                             base_url=bancos["vulnerable"]))
    plantillas = [c for c in r["comparacion"] if c["archivo"].endswith("TemplateController.java")]
    assert plantillas and plantillas[0]["estado"] != "CONFIRMADO_EXPLOTABLE"


def test_motor_sast_no_tiene_criterios(salida_temporal):
    r = motor.ejecutar(motor.ConfigEjecucion(escenario="vulnerable", modo="sast"))
    assert r["criterios"] == []
    assert r["configuraciones"][0]["id"] == "sast"


# --------------------------------------------------------------------------
# API web
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def web():
    from revia.web import servidor

    srv, url = servidor.arrancar(puerto=0, puerto_vulnerable=0, puerto_corregido=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield url
    srv.shutdown()
    srv.server_close()


def _post(url, cuerpo):
    req = urllib.request.Request(url, data=json.dumps(cuerpo).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_api_estado_e_interfaz(web):
    estado, cuerpo = _get(web + "/api/estado")
    datos = json.loads(cuerpo)
    assert estado == 200 and {e["id"] for e in datos["escenarios"]} == {"vulnerable", "corregido"}
    assert _get(web + "/")[0] == 200
    assert _get(web + "/static/app.js")[0] == 200


def test_api_prueba_compara_bancos(web):
    _, v = _post(web + "/api/prueba", {"caso": "ajeno", "escenario": "vulnerable"})
    _, c = _post(web + "/api/prueba", {"caso": "ajeno", "escenario": "corregido"})
    assert v["estado"] == 200 and "Bruno" in json.dumps(v["cuerpo"])
    assert c["estado"] == 403


def test_api_codigo_no_sale_del_escenario(web):
    assert _get(web + "/api/codigo?escenario=vulnerable&archivo=../pipeline/rules/java-spring.yml")[0] == 400
    assert _get(web + "/api/codigo?escenario=vulnerable&archivo=../../README.md")[0] == 400
    ok, texto = _get(web + "/api/codigo?escenario=vulnerable&archivo="
                     "order-service/src/main/java/com/seminario/order/OrderController.java")
    assert ok == 200 and "getOrder" in texto


def test_api_static_no_sale_de_la_carpeta(web):
    assert _get(web + "/static/../servidor.py")[0] in (400, 404)
