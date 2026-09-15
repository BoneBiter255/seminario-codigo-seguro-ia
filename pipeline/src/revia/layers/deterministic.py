"""Capa 1 - determinista. Es la fuente de verdad sintactica del pipeline.

Aporta cobertura y reproducibilidad: dado el mismo codigo y las mismas reglas
siempre devuelve exactamente los mismos hallazgos, sin llamadas de red y sin
variabilidad. Lo que NO aporta es criterio, y de ahi nace el problema que ataca
el resto del pipeline: esta capa sobre-reporta por diseno.

Hay dos analizadores y se complementan:

  * `RuleEngine` es el motor propio incluido en el repositorio. Funciona en
    cualquier maquina con solo Python y soporta reglas por AUSENCIA, que es
    como se expresan los fallos de autorizacion: el defecto no es una linea
    peligrosa, es una comprobacion que falta.
  * `SemgrepAdapter` delega en Semgrep cuando esta instalado, para contrastar
    contra una herramienta madura del estado del arte.

Ambos emiten `Finding`, asi que las capas siguientes no distinguen el origen.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..models import Finding, Severity


# --------------------------------------------------------------------------
# Enmascarado lexico
# --------------------------------------------------------------------------
# Contar llaves sobre el texto crudo es incorrecto: un literal como "{id}" o un
# comentario que dibuje un diagrama descuadran la profundidad. Se generan dos
# vistas del mismo buffer, ambas con la longitud original para que los
# desplazamientos sigan siendo validos contra el codigo fuente.

_COMILLAS = ('"', "'")


def _mask(source: str, mask_strings: bool) -> str:
    """Sustituye comentarios (y opcionalmente literales) por espacios."""
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if c == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
            continue

        if c == "/" and nxt == "*":
            while i < n and not (source[i] == "*" and i + 1 < n and source[i + 1] == "/"):
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            for _ in range(2):
                if i < n:
                    out[i] = " "
                    i += 1
            continue

        if c in _COMILLAS:
            quote = c
            start = i
            i += 1
            while i < n and source[i] != quote:
                if source[i] == "\\":
                    i += 1
                i += 1
            i = min(i + 1, n)
            if mask_strings:
                for j in range(start, i):
                    if source[j] != "\n":
                        out[j] = " "
            continue

        i += 1
    return "".join(out)


@dataclass(frozen=True)
class JavaMember:
    """Un miembro de clase (metodo o constructor) con sus anotaciones previas."""

    inicio: int
    fin: int
    texto_crudo: str
    texto_sin_comentarios: str


def extract_members(source: str) -> list[JavaMember]:
    """Extrae los bloques que abren en profundidad 1, es decir, el cuerpo de la clase.

    Trabajar por profundidad -- y no con una expresion regular de firma -- hace
    que funcionen las firmas partidas en varias lineas, los genericos y los
    constructores, que es justo donde una regex de firma falla.
    """
    braces = _mask(source, mask_strings=True)
    sin_comentarios = _mask(source, mask_strings=False)

    miembros: list[JavaMember] = []
    depth = 0
    apertura: int | None = None

    for i, c in enumerate(braces):
        if c == "{":
            if depth == 1:
                # Retrocede hasta el final del miembro anterior: eso arrastra las
                # anotaciones y el javadoc, que son contexto util para el triaje.
                j = i - 1
                while j >= 0 and braces[j] not in ";{}":
                    j -= 1
                apertura = j + 1
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 1 and apertura is not None:
                miembros.append(
                    JavaMember(
                        inicio=apertura,
                        fin=i + 1,
                        texto_crudo=source[apertura : i + 1],
                        texto_sin_comentarios=sin_comentarios[apertura : i + 1],
                    )
                )
                apertura = None
    return miembros


def _linea_de(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _fragmento(source: str, linea: int, contexto: int = 2) -> str:
    lineas = source.splitlines()
    ini = max(0, linea - 1 - contexto)
    fin = min(len(lineas), linea + contexto)
    return "\n".join(l.rstrip() for l in lineas[ini:fin]).strip()


def _finding_id(rule_id: str, archivo: str, linea: int) -> str:
    h = hashlib.sha1(f"{rule_id}|{archivo}|{linea}".encode()).hexdigest()[:8]
    return f"F-{h}"


# --------------------------------------------------------------------------
# Motor de reglas
# --------------------------------------------------------------------------


@dataclass
class Rule:
    id: str
    titulo: str
    cwe: str
    severidad: Severity
    tipo: str
    patron: re.Pattern[str]
    mensaje: str
    archivos: re.Pattern[str]
    ruido_esperado: str
    requiere: list[re.Pattern[str]]

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(
            id=d["id"],
            titulo=d["titulo"],
            cwe=d["cwe"],
            severidad=Severity(d["severidad"]),
            tipo=d.get("tipo", "presencia"),
            patron=re.compile(d["patron"]),
            mensaje=" ".join(d["mensaje"].split()),
            archivos=re.compile(d.get("archivos", r"\.java$")),
            ruido_esperado=d.get("ruido_esperado", "medio"),
            requiere=[re.compile(p) for p in d.get("requiere", [])],
        )


class RuleEngine:
    def __init__(self, rules_path: Path) -> None:
        data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
        self.reglas = [Rule.from_dict(r) for r in data["reglas"]]

    def scan_tree(self, raiz: Path) -> list[Finding]:
        hallazgos: list[Finding] = []
        for archivo in sorted(raiz.rglob("*.java")):
            hallazgos.extend(self.scan_file(archivo, raiz))
        return hallazgos

    def scan_file(self, archivo: Path, raiz: Path) -> list[Finding]:
        source = archivo.read_text(encoding="utf-8", errors="replace")
        rel = archivo.relative_to(raiz).as_posix()
        sin_comentarios = _mask(source, mask_strings=False)

        hallazgos: list[Finding] = []
        vistos: set[tuple[str, int]] = set()

        for regla in self.reglas:
            if not regla.archivos.search(rel):
                continue

            if regla.tipo == "presencia":
                impactos = [m.start() for m in regla.patron.finditer(sin_comentarios)]
            elif regla.tipo == "ausencia_en_metodo":
                impactos = []
                for miembro in extract_members(source):
                    ancla = regla.patron.search(miembro.texto_sin_comentarios)
                    if ancla is None:
                        continue
                    if any(req.search(miembro.texto_sin_comentarios) for req in regla.requiere):
                        continue  # la comprobacion existe: no hay hallazgo
                    impactos.append(miembro.inicio + ancla.start())
            else:
                raise ValueError(f"Tipo de regla desconocido: {regla.tipo}")

            for offset in impactos:
                linea = _linea_de(source, offset)
                if (regla.id, linea) in vistos:
                    continue
                vistos.add((regla.id, linea))
                hallazgos.append(
                    Finding(
                        id=_finding_id(regla.id, rel, linea),
                        rule_id=regla.id,
                        titulo=regla.titulo,
                        cwe=regla.cwe,
                        severidad=regla.severidad,
                        archivo=rel,
                        linea=linea,
                        fragmento=_fragmento(source, linea),
                        mensaje=regla.mensaje,
                        origen="sast-builtin",
                        ruido_esperado=regla.ruido_esperado,
                    )
                )
        return hallazgos


# --------------------------------------------------------------------------
# Adaptador Semgrep
# --------------------------------------------------------------------------

_SEVERIDAD_SEMGREP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepAdapter:
    """Ejecuta Semgrep si esta en el PATH. Si no lo esta, no hace nada.

    Deliberadamente no es un requisito duro: Semgrep no tiene soporte nativo en
    Windows y bloquear el pipeline por eso impediria reproducir el experimento
    en la maquina de desarrollo.
    """

    def __init__(self, config: str = "p/java") -> None:
        self.config = config

    @property
    def disponible(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan_tree(self, raiz: Path) -> list[Finding]:
        if not self.disponible:
            return []

        proc = subprocess.run(
            ["semgrep", "--config", self.config, "--json", "--quiet", str(raiz)],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if proc.returncode not in (0, 1) or not proc.stdout.strip():
            return []

        raiz_abs = raiz.resolve()
        hallazgos: list[Finding] = []
        for r in json.loads(proc.stdout).get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            cwe = meta.get("cwe")
            cwe_txt = (cwe[0] if isinstance(cwe, list) and cwe else cwe) or "CWE-desconocido"

            ruta = Path(r["path"]).resolve()
            rel_txt = ruta.relative_to(raiz_abs).as_posix() if ruta.is_relative_to(raiz_abs) else r["path"]
            linea = r["start"]["line"]

            hallazgos.append(
                Finding(
                    id=_finding_id(r["check_id"], rel_txt, linea),
                    rule_id=r["check_id"],
                    titulo=meta.get("shortDescription") or r["check_id"].rsplit(".", 1)[-1],
                    cwe=str(cwe_txt).split(":")[0],
                    severidad=_SEVERIDAD_SEMGREP.get(extra.get("severity", "WARNING"), Severity.MEDIUM),
                    archivo=rel_txt,
                    linea=linea,
                    fragmento=(extra.get("lines") or "").strip(),
                    mensaje=" ".join((extra.get("message") or "").split()),
                    origen="semgrep",
                    ruido_esperado="medio",
                )
            )
        return hallazgos


def run_deterministic_layer(raiz: Path, rules_path: Path, usar_semgrep: bool = True) -> list[Finding]:
    hallazgos = RuleEngine(rules_path).scan_tree(raiz)
    if usar_semgrep:
        hallazgos.extend(SemgrepAdapter().scan_tree(raiz))

    # Deduplicacion entre analizadores: dos herramientas que senalan el mismo
    # CWE en la misma linea son un hallazgo, no dos. Sin esto, anadir un
    # analizador infla artificialmente el conteo de falsos positivos y la
    # comparacion "SAST solo" vs "pipeline" deja de ser honesta.
    unicos: dict[tuple[str, int, str], Finding] = {}
    for h in hallazgos:
        clave = (h.archivo, h.linea, h.cwe)
        if clave not in unicos or h.severidad.rank > unicos[clave].severidad.rank:
            unicos[clave] = h

    return sorted(unicos.values(), key=lambda h: (-h.severidad.rank, h.archivo, h.linea))
