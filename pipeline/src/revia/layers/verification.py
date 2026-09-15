"""Capa 3 - verificacion independiente. El nucleo de la propuesta.

El principio que ordena todo el pipeline vive aqui: ningun veredicto se emite
sin evidencia independiente que lo respalde. El triaje produce una opinion; esta
capa produce un hecho reproducible, y el hecho manda sobre la opinion en ambas
direcciones.

Como lo hace: ejecuta una prueba de concepto real contra el servicio en marcha.
Para el IDOR cross-service, autentica a un usuario y le pide un recurso de OTRO
usuario; si el servicio devuelve la PII del tercero, la explotabilidad queda
confirmada con la respuesta HTTP como evidencia. Ese resultado puede:

  * ASCENDER un hallazgo que el triaje veia con dudas -> CONFIRMADO_EXPLOTABLE.
  * REFUTAR un hallazgo que el triaje daba por bueno -> REFUTADO_POR_POC.

Alcance honesto del prototipo: los PoC son plantillas parametrizadas por familia
de CWE, no codigo sintetizado libremente por el modelo. Es una decision
deliberada -- una PoC determinista es reproducible y segura de ejecutar en CI --
y a la vez la principal linea de trabajo futuro: que la capa de triaje proponga
la PoC y esta capa solo la ejecute en un sandbox.

Toda PoC corre contra un objetivo local y explicito. Esta capa nunca dispara
peticiones a un host que no le hayan pasado por parametro.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..models import Finding, TriageVerdict, VerificationResult

TIMEOUT_HTTP = 8


@dataclass
class ObjetivoEjecucion:
    """El servicio vivo contra el que se lanzan las PoC.

    `tokens_prueba` mapea un alias legible a una credencial valida del objetivo;
    las plantillas los usan para representar "atacante" y "victima" sin cablear
    secretos.
    """

    base_url: str
    tokens_prueba: dict[str, str]

    @property
    def disponible(self) -> bool:
        try:
            urllib.request.urlopen(self.base_url, timeout=2)
        except urllib.error.HTTPError:
            return True  # respondio (aunque sea 404): el proceso esta arriba
        except Exception:
            return False
        return True


def _get(url: str, headers: dict[str, str]) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_HTTP) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Plantillas de PoC por familia de CWE
# --------------------------------------------------------------------------


def _poc_idor(objetivo: ObjetivoEjecucion) -> VerificationResult:
    """IDOR: un usuario accede al recurso de otro y recibe su PII.

    Exito = el atacante obtiene, con SU token, datos cuyo propietario es la
    victima. Se comprueba sobre el contenido de la respuesta, no sobre el codigo
    de estado: un 200 vacio no prueba nada.
    """
    atacante = objetivo.tokens_prueba.get("atacante")
    recurso_victima = objetivo.tokens_prueba.get("recurso_victima", "ord-9")
    marcador_victima = objetivo.tokens_prueba.get("marcador_victima", "u-2002")

    if atacante is None:
        return VerificationResult(
            intentada=False,
            explotabilidad_confirmada=False,
            motivo_omision="No se configuro un token de atacante para el objetivo.",
        )

    url = f"{objetivo.base_url}/api/orders/{recurso_victima}"
    estado, cuerpo = _get(url, {"Authorization": f"Bearer {atacante}"})

    filtrado = estado == 200 and marcador_victima in cuerpo
    pasos = [
        "PoC IDOR cross-service:",
        f"  1. Atacante autenticado con su propio token.",
        f"  2. GET {url}  (recurso cuyo propietario es {marcador_victima}).",
        f"  3. Respuesta HTTP {estado}.",
    ]
    if filtrado:
        try:
            datos = json.loads(cuerpo)
            pii = datos.get("owner", {})
            pasos.append(f"  4. Se filtro PII del propietario: {pii.get('nombre')} / {pii.get('documento')}.")
        except json.JSONDecodeError:
            pasos.append("  4. La respuesta contiene el identificador de la victima.")
        pasos.append("  => EXPLOTABILIDAD CONFIRMADA: acceso a recurso ajeno concedido.")
    else:
        pasos.append("  => No explotable: el servicio nego el acceso o no filtro datos ajenos.")

    return VerificationResult(
        intentada=True,
        explotabilidad_confirmada=filtrado,
        poc_ruta=f"GET /api/orders/{recurso_victima}",
        codigo_salida=estado,
        evidencia="\n".join(pasos),
    )


def _poc_confianza_cabecera(objetivo: ObjetivoEjecucion) -> VerificationResult:
    """Control por cabecera falsificable: enviar la cabecera 'de confianza' desde fuera."""
    recurso_victima = objetivo.tokens_prueba.get("recurso_victima_interno", "u-2002")
    url = f"{objetivo.base_url}/internal/users/{recurso_victima}"

    estado_con, cuerpo_con = _get(url, {"X-Internal-Call": "true"})
    estado_sin, _ = _get(url, {})

    concedido = estado_con == 200 and recurso_victima in cuerpo_con and estado_sin != 200
    pasos = [
        "PoC confianza en cabecera interna:",
        f"  1. GET {url} con cabecera X-Internal-Call:true  -> HTTP {estado_con}.",
        f"  2. GET {url} sin la cabecera                     -> HTTP {estado_sin}.",
    ]
    pasos.append(
        "  => EXPLOTABLE: la unica barrera es una cabecera que el cliente elige poner."
        if concedido
        else "  => No concluyente en este objetivo."
    )
    return VerificationResult(
        intentada=True,
        explotabilidad_confirmada=concedido,
        poc_ruta=f"GET /internal/users/{recurso_victima}",
        codigo_salida=estado_con,
        evidencia="\n".join(pasos),
    )


# Mapa CWE -> plantilla de PoC. Solo lo que se puede demostrar de forma segura y
# reproducible tiene entrada aqui; el resto queda como PROBABLE_NO_VERIFICADO.
PLANTILLAS = {
    "CWE-639": _poc_idor,
    "CWE-290": _poc_confianza_cabecera,
}


@dataclass
class VerificationLayer:
    objetivo: ObjetivoEjecucion | None

    def verify(self, finding: Finding, triaje: TriageVerdict) -> VerificationResult:
        plantilla = PLANTILLAS.get(finding.cwe)
        if plantilla is None:
            return VerificationResult(
                intentada=False,
                explotabilidad_confirmada=False,
                motivo_omision=f"No hay plantilla de PoC para {finding.cwe} en el prototipo.",
            )
        if not triaje.verificable_dinamicamente:
            return VerificationResult(
                intentada=False,
                explotabilidad_confirmada=False,
                motivo_omision="El triaje marco el hallazgo como no verificable dinamicamente.",
            )
        if self.objetivo is None or not self.objetivo.disponible:
            return VerificationResult(
                intentada=False,
                explotabilidad_confirmada=False,
                motivo_omision="El objetivo no esta en ejecucion; no se pudo lanzar la PoC.",
            )
        return plantilla(self.objetivo)


def run_verification_layer(
    findings: list[Finding],
    triajes: dict[str, TriageVerdict],
    objetivo: ObjetivoEjecucion | None,
) -> dict[str, VerificationResult]:
    capa = VerificationLayer(objetivo=objetivo)
    resultados: dict[str, VerificationResult] = {}
    for f in findings:
        triaje = triajes.get(f.id)
        if triaje is None or triaje.veredicto == "falso_positivo":
            # No se gasta una PoC en lo que el triaje ya descarto.
            continue
        resultado = capa.verify(f, triaje)
        if resultado.intentada:
            marca = "CONFIRMADA" if resultado.explotabilidad_confirmada else "refutada"
            print(f"[verificacion] {f.id}  {f.cwe}  PoC {marca}")
        resultados[f.id] = resultado
    return resultados
