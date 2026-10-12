"""Escenarios de prueba: que codigo se analiza, contra que verdad de terreno se
mide y en que modo corre el banco ejecutable.

    vulnerable -> target/            el banco con el IDOR cross-service
    corregido  -> target-corregido/  el mismo codigo con el fix (grupo de control)

La unica diferencia entre ambos es el fix de la cadena cross-service, asi que
comparar sus resultados aisla el efecto de la correccion.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
REGLAS = REPO / "pipeline" / "rules" / "java-spring.yml"
CRITERIOS = REPO / "dataset" / "criterios.yml"


@dataclass(frozen=True)
class Escenario:
    id: str
    nombre: str
    descripcion: str
    raiz: Path
    dataset: Path
    modo_banco: str

    def resumen(self) -> dict:
        return {
            "id": self.id,
            "nombre": self.nombre,
            "descripcion": self.descripcion,
            "raiz": self.raiz.relative_to(REPO).as_posix(),
            "dataset": self.dataset.relative_to(REPO).as_posix(),
            "modo_banco": self.modo_banco,
        }


ESCENARIOS: dict[str, Escenario] = {
    "vulnerable": Escenario(
        id="vulnerable",
        nombre="Vulnerable",
        descripcion="Tres microservicios con un IDOR cross-service inyectado y 19 hallazgos etiquetados.",
        raiz=REPO / "target",
        dataset=REPO / "dataset" / "ground-truth.yml",
        modo_banco="vulnerable",
    ),
    "corregido": Escenario(
        id="corregido",
        nombre="Corregido (control)",
        descripcion="El mismo codigo con el fix aplicado. Ninguna PoC deberia confirmar nada aqui.",
        raiz=REPO / "target-corregido",
        dataset=REPO / "dataset" / "ground-truth-corregido.yml",
        modo_banco="corregido",
    ),
}
