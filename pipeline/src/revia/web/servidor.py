"""Servidor de la interfaz web de REVIA.

Solo usa la biblioteca estandar. Al arrancar:

  1. levanta los dos bancos de pruebas en hilos (vulnerable y corregido),
  2. sirve la interfaz (static/) y una API JSON pequena,
  3. corre el pipeline en un hilo aparte cuando la interfaz lo pide y guarda
     sus eventos para que la pagina los consulte cada pocos cientos de ms.

Uso:
    python -m revia.web.servidor            # abre http://127.0.0.1:8765
    python -m revia.web.servidor --sin-navegador
"""

from __future__ import annotations

import argparse
import difflib
import json
import mimetypes
import os
import socket
import sys
import threading
import traceback
import urllib.error
import urllib.request
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..escenarios import ESCENARIOS, REPO
from ..layers.triage import MODELOS_POR_DEFECTO, _ollama_modelos
from ..motor import MODOS, SALIDA_WEB, ConfigEjecucion, cargar_ejecucion, ejecutar, listar_ejecuciones

sys.path.insert(0, str(REPO / "target" / "mock"))
from run_target import arrancar_en_hilo  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"

# Peticiones de la pantalla "Escenarios de prueba": el uso normal y el caso que
# el banco vulnerable no deberia permitir. Son las mismas de VER-EL-ATAQUE.bat.
PRUEBAS = {
    "propios": {
        "titulo": "Ana lista sus pedidos",
        "tipo": "normal",
        "ruta": "/api/orders",
        "cabeceras": {"Authorization": "Bearer token-ana"},
        "esperado": "200 con solo los pedidos de Ana",
    },
    "propio_detalle": {
        "titulo": "Ana abre su pedido ord-1",
        "tipo": "normal",
        "ruta": "/api/orders/ord-1",
        "cabeceras": {"Authorization": "Bearer token-ana"},
        "esperado": "200: el pedido es suyo",
    },
    "ajeno": {
        "titulo": "Ana abre el pedido ord-9 (de Bruno)",
        "tipo": "ataque",
        "ruta": "/api/orders/ord-9",
        "cabeceras": {"Authorization": "Bearer token-ana"},
        "esperado": "403: el pedido no es suyo",
    },
    "sin_token": {
        "titulo": "Sin autenticarse",
        "tipo": "control",
        "ruta": "/api/orders/ord-9",
        "cabeceras": {},
        "esperado": "401: no hay sesion",
    },
}


class Corrida:
    """Una ejecucion del pipeline en segundo plano y sus eventos."""

    def __init__(self, config: ConfigEjecucion) -> None:
        self.config = config
        self.eventos: list[dict] = []
        self.terminado = False
        self.error: str | None = None
        self.resultado_id: str | None = None
        self._lock = threading.Lock()

    def emitir(self, evento: dict) -> None:
        with self._lock:
            self.eventos.append(evento)

    def desde(self, n: int) -> list[dict]:
        with self._lock:
            return self.eventos[n:]

    def correr(self) -> None:
        try:
            resultado = ejecutar(self.config, self.emitir)
            self.resultado_id = resultado["id"]
        except Exception as exc:  # se muestra en la interfaz, no se pierde
            traceback.print_exc()
            self.error = f"{type(exc).__name__}: {exc}"
            self.emitir({"tipo": "error", "mensaje": self.error})
        finally:
            self.terminado = True


class Estado:
    def __init__(self) -> None:
        self.trafico: deque = deque(maxlen=300)
        self.bancos: dict[str, str] = {}
        self.corrida: Corrida | None = None
        self.lock = threading.Lock()


ESTADO = Estado()


def _puerto(preferido: int) -> int:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", preferido))
            return preferido
        except OSError:
            return 0


def _get(url: str, headers: dict[str, str]) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except OSError as e:
        return 0, str(e)


def _proveedores() -> dict:
    modelos = _ollama_modelos()
    return {
        "ollama": {"disponible": modelos is not None,
                   "modelos": [m for m in (modelos or []) if "embed" not in m],
                   "por_defecto": MODELOS_POR_DEFECTO["ollama"]},
        "gemini": {"disponible": bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")),
                   "por_defecto": MODELOS_POR_DEFECTO["gemini"]},
        "groq": {"disponible": bool(os.getenv("GROQ_API_KEY")), "por_defecto": MODELOS_POR_DEFECTO["groq"]},
        "claude": {"disponible": bool(os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN")),
                   "por_defecto": MODELOS_POR_DEFECTO["claude"]},
    }


def _archivos_java(raiz: Path) -> list[str]:
    return sorted(p.relative_to(raiz).as_posix() for p in raiz.rglob("*.java"))


def _diff_fix() -> list[dict]:
    a, b = ESCENARIOS["vulnerable"].raiz, ESCENARIOS["corregido"].raiz
    out = []
    for rel in _archivos_java(a):
        va = (a / rel).read_text(encoding="utf-8").splitlines()
        pb = b / rel
        vb = pb.read_text(encoding="utf-8").splitlines() if pb.exists() else []
        if va != vb:
            out.append({"archivo": rel, "diff": "\n".join(difflib.unified_diff(
                va, vb, "vulnerable/" + rel, "corregido/" + rel, lineterm="", n=3))})
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        pass

    # ------------------------------------------------------------ utilidades

    def _json(self, datos, estado: int = 200) -> None:
        cuerpo = json.dumps(datos, ensure_ascii=False).encode("utf-8")
        self.send_response(estado)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(cuerpo)

    def _archivo(self, ruta: Path, tipo: str | None = None) -> None:
        if not ruta.is_file():
            return self._json({"error": "no encontrado"}, 404)
        cuerpo = ruta.read_bytes()
        tipo = tipo or mimetypes.guess_type(ruta.name)[0] or "application/octet-stream"
        if tipo.startswith("text/") or tipo in ("application/javascript", "application/json"):
            tipo += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(cuerpo)

    def _leer_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except ValueError:
            return {}

    # ----------------------------------------------------------------- rutas

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        ruta = url.path

        if ruta in ("/", "/index.html"):
            return self._archivo(STATIC / "index.html", "text/html")
        if ruta.startswith("/static/"):
            destino = (STATIC / ruta[len("/static/"):]).resolve()
            if STATIC.resolve() not in destino.parents:
                return self._json({"error": "ruta invalida"}, 400)
            return self._archivo(destino)

        if ruta == "/api/estado":
            corrida = ESTADO.corrida
            return self._json({
                "escenarios": [e.resumen() for e in ESCENARIOS.values()],
                "bancos": ESTADO.bancos,
                "proveedores": _proveedores(),
                "modos": list(MODOS),
                "pruebas": PRUEBAS,
                "corriendo": bool(corrida and not corrida.terminado),
            })

        if ruta == "/api/trafico":
            desde = int(q.get("desde", 0))
            todo = list(ESTADO.trafico)
            return self._json({"total": len(todo), "entradas": todo[desde:] if desde <= len(todo) else todo})

        if ruta == "/api/corrida":
            corrida = ESTADO.corrida
            if corrida is None:
                return self._json({"existe": False})
            return self._json({
                "existe": True,
                "terminado": corrida.terminado,
                "error": corrida.error,
                "resultado_id": corrida.resultado_id,
                "eventos": corrida.desde(int(q.get("desde", 0))),
            })

        if ruta == "/api/ejecuciones":
            return self._json(listar_ejecuciones())
        if ruta.startswith("/api/ejecuciones/"):
            r = cargar_ejecucion(ruta.rsplit("/", 1)[-1])
            return self._json(r) if r else self._json({"error": "no encontrada"}, 404)
        if ruta.startswith("/api/reporte/"):
            id_ = Path(ruta.rsplit("/", 1)[-1]).name
            return self._archivo(SALIDA_WEB / id_ / "reporte.md", "text/markdown")

        if ruta == "/api/archivos":
            esc = ESCENARIOS.get(q.get("escenario", "vulnerable"))
            if esc is None:
                return self._json({"error": "escenario desconocido"}, 400)
            return self._json(_archivos_java(esc.raiz))
        if ruta == "/api/codigo":
            esc = ESCENARIOS.get(q.get("escenario", "vulnerable"))
            if esc is None:
                return self._json({"error": "escenario desconocido"}, 400)
            destino = (esc.raiz / q.get("archivo", "")).resolve()
            if esc.raiz.resolve() not in destino.parents or destino.suffix != ".java":
                return self._json({"error": "ruta invalida"}, 400)
            return self._archivo(destino, "text/plain")
        if ruta == "/api/diff":
            return self._json(_diff_fix())

        self._json({"error": "no encontrado"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        ruta = urlparse(self.path).path
        datos = self._leer_json()

        if ruta == "/api/prueba":
            prueba = PRUEBAS.get(datos.get("caso", ""))
            esc = ESCENARIOS.get(datos.get("escenario", "vulnerable"))
            if prueba is None or esc is None:
                return self._json({"error": "caso o escenario desconocido"}, 400)
            base = ESTADO.bancos[esc.modo_banco]
            estado, cuerpo = _get(base + prueba["ruta"], prueba["cabeceras"])
            try:
                cuerpo_json = json.loads(cuerpo) if cuerpo else None
            except ValueError:
                cuerpo_json = None
            return self._json({"caso": datos["caso"], "escenario": esc.id, "url": base + prueba["ruta"],
                               "cabeceras": prueba["cabeceras"], "estado": estado,
                               "cuerpo": cuerpo_json if cuerpo_json is not None else cuerpo})

        if ruta == "/api/ejecuciones":
            with ESTADO.lock:
                if ESTADO.corrida and not ESTADO.corrida.terminado:
                    return self._json({"error": "ya hay un analisis en curso"}, 409)
                esc = ESCENARIOS.get(datos.get("escenario", "vulnerable"))
                modo = datos.get("modo", "llm")
                if esc is None or modo not in MODOS:
                    return self._json({"error": "escenario o modo desconocido"}, 400)
                config = ConfigEjecucion(
                    escenario=esc.id,
                    modo=modo,
                    proveedor=datos.get("proveedor") or "auto",
                    modelo=datos.get("modelo") or None,
                    razonamiento={"si": True, "no": False}.get(datos.get("razonamiento")),
                    base_url=ESTADO.bancos[esc.modo_banco],
                    base_url_corregido=ESTADO.bancos["corregido"],
                )
                ESTADO.corrida = Corrida(config)
                threading.Thread(target=ESTADO.corrida.correr, daemon=True, name="corrida").start()
            return self._json({"ok": True}, 202)

        self._json({"error": "no encontrado"}, 404)


def arrancar(puerto: int = 8765, puerto_vulnerable: int = 8081, puerto_corregido: int = 8082
             ) -> tuple[ThreadingHTTPServer, str]:
    for modo, preferido in (("vulnerable", puerto_vulnerable), ("corregido", puerto_corregido)):
        _, url = arrancar_en_hilo(modo, port=_puerto(preferido), trafico=ESTADO.trafico)
        ESTADO.bancos[modo] = url
    servidor = ThreadingHTTPServer(("127.0.0.1", _puerto(puerto)), Handler)
    servidor.daemon_threads = True
    return servidor, f"http://127.0.0.1:{servidor.server_address[1]}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Interfaz web de REVIA")
    parser.add_argument("--puerto", type=int, default=8765)
    parser.add_argument("--sin-navegador", action="store_true")
    args = parser.parse_args(argv)

    servidor, url = arrancar(args.puerto)
    print(f"[revia] interfaz en {url}")
    print(f"[revia] banco vulnerable en {ESTADO.bancos['vulnerable']}")
    print(f"[revia] banco corregido  en {ESTADO.bancos['corregido']}")
    print("[revia] Ctrl+C para detener")
    if not args.sin_navegador:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[revia] detenido")
    finally:
        servidor.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
