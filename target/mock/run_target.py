"""Replica ejecutable del banco de pruebas vulnerable.

Reproduce el MISMO contrato HTTP que los microservicios Spring de
`target/order-service` y `target/user-service`, incluida la ausencia de
verificacion de propiedad en GET /api/orders/{orderId}.

Existe por una razon concreta: la capa de verificacion del pipeline necesita un
objetivo vivo contra el cual lanzar la prueba de concepto. Levantar los dos
servicios Spring exige Maven y una JVM compatible; este proceso solo necesita
Python de la biblioteca estandar, asi que la demostracion de explotabilidad se
puede correr en cualquier maquina y en CI.

El codigo Java sigue siendo el artefacto que analiza la capa determinista.
Este modulo es el banco de pruebas en runtime, no un sustituto del analisis.

Uso:
    python target/mock/run_target.py --port 8081
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

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


def resolve_user(authorization: str | None) -> str | None:
    if not authorization:
        return None
    return TOKENS.get(authorization.replace("Bearer ", "").strip())


class TargetHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, payload: object | None = None) -> None:
        body = b"" if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # silencia el log por peticion
        pass

    def do_GET(self) -> None:  # noqa: N802  (firma impuesta por BaseHTTPRequestHandler)
        path = urlparse(self.path).path
        parts = [p for p in path.split("/") if p]

        # GET /internal/users/{userId}  -> InternalUserController
        if parts[:2] == ["internal", "users"] and len(parts) == 3:
            if self.headers.get("X-Internal-Call") != "true":
                return self._send(403)
            user = USERS.get(parts[2])
            return self._send(200, user) if user else self._send(404)

        # GET /api/orders  -> listMyOrders (ruta correcta)
        if parts == ["api", "orders"]:
            caller = resolve_user(self.headers.get("Authorization"))
            if caller is None:
                return self._send(401)
            return self._send(200, [o for o in ORDERS.values() if o["ownerId"] == caller])

        # GET /api/orders/{orderId}  -> getOrder (IDOR cross-service)
        if parts[:2] == ["api", "orders"] and len(parts) == 3:
            caller = resolve_user(self.headers.get("Authorization"))
            if caller is None:
                return self._send(401)
            order = ORDERS.get(parts[2])
            if order is None:
                return self._send(404)
            # Aqui deberia ir:  if order["ownerId"] != caller: return self._send(403)
            # Su ausencia ES la vulnerabilidad.
            body = dict(order)
            body["owner"] = USERS.get(order["ownerId"])  # PII del tercero
            return self._send(200, body)

        self._send(404)


def main() -> None:
    parser = argparse.ArgumentParser(description="Banco de pruebas vulnerable (order + user en un proceso)")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), TargetHandler)
    print(f"[target] escuchando en http://{args.host}:{args.port}")
    print("[target] rutas: /api/orders  /api/orders/{id}  /internal/users/{id}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[target] detenido")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
