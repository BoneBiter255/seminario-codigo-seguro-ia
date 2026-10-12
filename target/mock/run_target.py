"""Replica ejecutable del banco de pruebas.

Reproduce el MISMO contrato HTTP que los microservicios Spring de
`target/order-service` y `target/user-service`, incluida la ausencia de
verificacion de propiedad en GET /api/orders/{orderId}.

Existe por una razon concreta: la capa de verificacion del pipeline necesita un
objetivo vivo contra el cual lanzar la prueba de concepto. Levantar los dos
servicios Spring exige Maven y una JVM compatible; este proceso solo necesita
Python de la biblioteca estandar, asi que la demostracion de explotabilidad se
puede correr en cualquier maquina y en CI.

Tiene dos modos, uno por cada version del codigo Java:

  * `vulnerable` -> espejo de `target/` (IDOR + cabecera interna falsificable).
  * `corregido`  -> espejo de `target-corregido/`: getOrder compara el
    propietario y /internal/users exige el token de servicio.

El codigo Java sigue siendo el artefacto que analiza la capa determinista.
Este modulo es el banco de pruebas en runtime, no un sustituto del analisis.

Uso:
    python target/mock/run_target.py --port 8081
    python target/mock/run_target.py --port 8082 --modo corregido
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import threading
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

MODOS = ("vulnerable", "corregido")

# Espejo de UserRepository.java
USERS = {
    "u-1001": {
        "id": "u-1001",
        "nombre": "Ana Martinez",
        "email": "ana@example.com",
        "documento": "CC-1020304050",
        "telefono": "+57 300 111 2233",
    },
    "u-2002": {
        "id": "u-2002",
        "nombre": "Bruno Salcedo",
        "email": "bruno@example.com",
        "documento": "CC-8070605040",
        "telefono": "+57 301 444 5566",
    },
}

# Espejo de OrderRepository.java
ORDERS = {
    "ord-1": {"id": "ord-1", "ownerId": "u-1001", "descripcion": "Suscripcion anual", "total": 480000},
    "ord-2": {"id": "ord-2", "ownerId": "u-1001", "descripcion": "Soporte premium", "total": 120000},
    "ord-9": {"id": "ord-9", "ownerId": "u-2002", "descripcion": "Consultoria confidencial", "total": 9500000},
}

# Espejo de AuthService.TOKEN_TO_USER
TOKENS = {"token-ana": "u-1001", "token-bruno": "u-2002"}

# Espejo de AuthService.INTERNAL_API_TOKEN: lo que order-service presenta a
# user-service. En modo corregido es la unica forma de entrar a /internal/users.
SERVICE_TOKEN = "s3cr3t-internal-token-2026"


def resolve_user(authorization: str | None) -> str | None:
    if not authorization:
        return None
    return TOKENS.get(authorization.replace("Bearer ", "").strip())


class TargetHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    modo = "vulnerable"
    trafico: deque | None = None
    """Si se asigna, cada peticion atendida se anota aqui (lo usa la consola web)."""

    def _send(self, status: int, payload: object | None = None) -> None:
        body = b"" if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)
        if self.trafico is not None:
            self.trafico.append({
                "hora": dt.datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "modo": self.modo,
                "metodo": self.command,
                "ruta": self.path,
                "autorizacion": self.headers.get("Authorization"),
                "cabeceras_internas": {
                    k: v for k, v in self.headers.items() if k.lower().startswith("x-internal")
                },
                "estado": status,
            })

    def log_message(self, fmt: str, *args) -> None:  # silencia el log por peticion
        pass

    def do_GET(self) -> None:  # noqa: N802  (firma impuesta por BaseHTTPRequestHandler)
        path = urlparse(self.path).path
        parts = [p for p in path.split("/") if p]
        corregido = self.modo == "corregido"

        # GET /internal/users/{userId}  -> InternalUserController
        if parts[:2] == ["internal", "users"] and len(parts) == 3:
            if corregido:
                if self.headers.get("X-Internal-Token") != SERVICE_TOKEN:
                    return self._send(403)
            elif self.headers.get("X-Internal-Call") != "true":
                return self._send(403)
            user = USERS.get(parts[2])
            return self._send(200, user) if user else self._send(404)

        # GET /api/orders  -> listMyOrders
        if parts == ["api", "orders"]:
            caller = resolve_user(self.headers.get("Authorization"))
            if caller is None:
                return self._send(401)
            return self._send(200, [o for o in ORDERS.values() if o["ownerId"] == caller])

        # GET /api/orders/{orderId}  -> getOrder
        if parts[:2] == ["api", "orders"] and len(parts) == 3:
            caller = resolve_user(self.headers.get("Authorization"))
            if caller is None:
                return self._send(401)
            order = ORDERS.get(parts[2])
            if order is None:
                return self._send(404)
            # En modo vulnerable falta esta comprobacion: su ausencia ES el IDOR.
            if corregido and order["ownerId"] != caller:
                return self._send(403)
            body = dict(order)
            body["owner"] = USERS.get(order["ownerId"])  # perfil via user-service
            return self._send(200, body)

        self._send(404)


def crear_servidor(host: str, port: int, modo: str = "vulnerable",
                   trafico: deque | None = None) -> ThreadingHTTPServer:
    """Servidor del banco en el modo pedido. port=0 elige un puerto libre."""
    if modo not in MODOS:
        raise ValueError(f"modo desconocido: {modo}")
    handler = type(f"TargetHandler_{modo}", (TargetHandler,), {"modo": modo, "trafico": trafico})
    return ThreadingHTTPServer((host, port), handler)


def arrancar_en_hilo(modo: str = "vulnerable", port: int = 0, host: str = "127.0.0.1",
                     trafico: deque | None = None) -> tuple[ThreadingHTTPServer, str]:
    """Levanta el banco en un hilo daemon y devuelve (servidor, url_base)."""
    server = crear_servidor(host, port, modo, trafico)
    threading.Thread(target=server.serve_forever, daemon=True, name=f"banco-{modo}").start()
    return server, f"http://{host}:{server.server_address[1]}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Banco de pruebas (order + user en un proceso)")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--modo", choices=MODOS, default="vulnerable")
    args = parser.parse_args()

    server = crear_servidor(args.host, args.port, args.modo)
    print(f"[target] modo {args.modo}, escuchando en http://{args.host}:{args.port}")
    print("[target] rutas: /api/orders  /api/orders/{id}  /internal/users/{id}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[target] detenido")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
