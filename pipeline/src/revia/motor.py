"""Motor del pipeline con eventos, pensado para la interfaz web.

Hace lo mismo que `revia.pipeline` (determinista -> triaje -> verificacion ->
reporte + metricas), pero hallazgo por hallazgo y avisando de cada paso con un
evento. Asi la interfaz puede mostrar en vivo que entra al modelo, que
responde, cuanto tarda y que demuestra la PoC.

Ademas de las tres capas agrega dos cosas que el CLI no hace:

  * Comparacion en la misma corrida: el triaje sin IA (baseline) se calcula
    siempre, aunque se use un LLM, para medir ambos sobre los MISMOS hallazgos.
  * Validacion del fix: para cada hallazgo confirmado en el escenario
    vulnerable se re-escanea la version corregida, se repite la misma PoC
    contra el banco corregido y se comprueba que el uso legitimo siga
    funcionando (prueba de regresion).
"""

from __future__ import annotations

import datetime as dt
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from .escenarios import CRITERIOS, ESCENARIOS, REGLAS, REPO
from .evaluation.metrics import Confusion, GroundTruth, evaluar, formatear
from .layers.deterministic import run_deterministic_layer
from .layers.triage import SYSTEM_PROMPT, TriageLayer
from .layers.verification import ObjetivoEjecucion, VerificationLayer
from .models import FinalStatus, PipelineReport, ReviewedFinding, TriageVerdict, VerificationResult
from .pipeline import OBJETIVO_PRUEBA
from .report.render import escribir_reportes

MODOS = ("sast", "baseline", "llm")
SALIDA_WEB = REPO / "out" / "web"

Emisor = Callable[[dict], None]


@dataclass
class ConfigEjecucion:
    escenario: str = "vulnerable"
    modo: str = "llm"                 # sast | baseline | llm
    proveedor: str = "auto"
    modelo: str | None = None
    razonamiento: bool | None = None  # solo Ollama: modo de razonamiento del modelo
    base_url: str | None = None       # banco del escenario, para las PoC
    base_url_corregido: str | None = None  # banco corregido, para validar el fix


def _confusion(nombre: str, id_: str, c: Confusion) -> dict:
    return {
        "id": id_, "nombre": nombre,
        "tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn,
        "precision": round(c.precision, 3), "recall": round(c.recall, 3),
        "f1": round(c.f1, 3), "tasa_fp": round(c.tasa_fp, 3),
    }


def _ensamblar(findings, triajes, verificaciones) -> list[ReviewedFinding]:
    revisados = []
    for f in findings:
        rf = ReviewedFinding(finding=f, triaje=triajes.get(f.id), verificacion=verificaciones.get(f.id))
        rf.resolver_estado()
        revisados.append(rf)
    return revisados


def _verificar(capa: VerificationLayer, findings, triajes, previas=None) -> dict[str, VerificationResult]:
    """Misma politica que run_verification_layer, reutilizando resultados ya obtenidos."""
    previas = previas or {}
    out: dict[str, VerificationResult] = {}
    for f in findings:
        t = triajes.get(f.id)
        if t is None or t.veredicto == "falso_positivo":
            continue
        out[f.id] = previas.get(f.id) or capa.verify(f, t)
    return out


def _get(url: str, headers: dict[str, str]) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except OSError as e:
        return 0, str(e)


def evaluar_criterios(metricas: dict, escenario: str) -> list[dict]:
    datos = yaml.safe_load(CRITERIOS.read_text(encoding="utf-8"))["criterios"]
    out = []
    for c in datos:
        if c["escenario"] != escenario:
            continue
        valor = metricas.get(c["metrica"])
        if valor is None:
            cumple = None
        elif c["operador"] == ">=":
            cumple = valor >= c["umbral"]
        else:
            cumple = valor <= c["umbral"]
        out.append({**c, "valor": valor, "cumple": cumple})
    return out


def ejecutar(config: ConfigEjecucion, emitir: Emisor = lambda e: None) -> dict:
    if config.modo not in MODOS:
        raise ValueError(f"modo desconocido: {config.modo}")
    esc = ESCENARIOS[config.escenario]
    gt = GroundTruth(esc.dataset)
    inicio = time.perf_counter()
    id_ejec = dt.datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{esc.id}-{config.modo}"

    def ev(tipo: str, **datos) -> None:
        emitir({"tipo": tipo, "t": round(time.perf_counter() - inicio, 3), **datos})

    ev("inicio", id=id_ejec, escenario=esc.resumen(), modo=config.modo,
       proveedor=config.proveedor, modelo=config.modelo)
    tiempos: dict[str, float] = {}

    # -- Capa 1: determinista ------------------------------------------------
    ev("capa", capa=1, estado="inicio")
    t0 = time.perf_counter()
    findings = run_deterministic_layer(esc.raiz, REGLAS, usar_semgrep=False)
    tiempos["determinista_s"] = time.perf_counter() - t0
    for f in findings:
        etiqueta = gt.lookup(f.rule_id, f.archivo)
        ev("hallazgo", hallazgo=f.model_dump(mode="json"),
           real=None if etiqueta is None else etiqueta.etiqueta)
    ev("capa", capa=1, estado="fin", ms=round(tiempos["determinista_s"] * 1000),
       total=len(findings))

    # -- Capa 2: triaje ------------------------------------------------------
    triajes: dict[str, TriageVerdict] = {}
    base_capa = TriageLayer(raiz=esc.raiz, usar_ia=False)
    triajes_base = {f.id: base_capa.triage(f) for f in findings}
    tiempos_triaje: list[float] = []
    etiqueta_triaje = None
    capa = None

    if config.modo != "sast":
        ev("capa", capa=2, estado="inicio")
        t0 = time.perf_counter()
        capa = TriageLayer(raiz=esc.raiz, modelo=config.modelo, proveedor=config.proveedor,
                           usar_ia=config.modo == "llm", razonamiento=config.razonamiento)
        if config.modo == "llm" and not capa.usar_ia:
            ev("aviso", mensaje="No hay proveedor de LLM disponible: el triaje usa el baseline sin IA.")
        ev("triaje_config", etiqueta=capa.etiqueta, usar_ia=capa.usar_ia,
           prompt_sistema=SYSTEM_PROMPT if capa.usar_ia else None)
        for i, f in enumerate(findings, 1):
            ev("triaje_inicio", id=f.id, n=i, total=len(findings),
               prompt=capa._prompt_usuario(f) if capa.usar_ia else None)
            t1 = time.perf_counter()
            v = capa.triage(f)
            seg = time.perf_counter() - t1
            tiempos_triaje.append(seg)
            triajes[f.id] = v
            ev("triaje_fin", id=f.id, veredicto=v.model_dump(mode="json"), ms=round(seg * 1000),
               degradado=v.razonamiento.startswith("[degradado"))
        tiempos["triaje_s"] = time.perf_counter() - t0
        etiqueta_triaje = capa.etiqueta
        if capa.usar_ia and capa.proveedor == "ollama" and config.razonamiento is False:
            etiqueta_triaje += " sin razonamiento"
        if capa.degradados:
            etiqueta_triaje += f" ({capa.degradados}/{len(findings)} degradados a heuristica)"
        ev("capa", capa=2, estado="fin", ms=round(tiempos["triaje_s"] * 1000))

    # -- Capa 3: verificacion ------------------------------------------------
    verificaciones: dict[str, VerificationResult] = {}
    objetivo = None
    if config.base_url:
        objetivo = ObjetivoEjecucion(base_url=config.base_url, tokens_prueba=OBJETIVO_PRUEBA)
        if not objetivo.disponible:
            ev("aviso", mensaje=f"El banco {config.base_url} no responde: se omiten las PoC.")
            objetivo = None
    capa_v = VerificationLayer(objetivo=objetivo)
    if config.modo != "sast":
        ev("capa", capa=3, estado="inicio", banco=config.base_url if objetivo else None)
        t0 = time.perf_counter()
        for f in findings:
            t = triajes.get(f.id)
            if t is None or t.veredicto == "falso_positivo":
                continue
            r = capa_v.verify(f, t)
            verificaciones[f.id] = r
            ev("verificacion", id=f.id, resultado=r.model_dump(mode="json"))
        tiempos["verificacion_s"] = time.perf_counter() - t0
        ev("capa", capa=3, estado="fin", ms=round(tiempos["verificacion_s"] * 1000))

    revisados = _ensamblar(findings, triajes, verificaciones)
    for rf in revisados:
        ev("estado", id=rf.finding.id, estado=rf.estado.value)

    # -- Validacion del fix --------------------------------------------------
    fixes: list[dict] = []
    confirmados = [rf for rf in revisados if rf.estado == FinalStatus.CONFIRMADO_EXPLOTABLE]
    if esc.id == "vulnerable" and confirmados and config.base_url_corregido:
        ev("capa", capa=4, estado="inicio")
        t0 = time.perf_counter()
        corregido = ESCENARIOS["corregido"]
        hallazgos_c = run_deterministic_layer(corregido.raiz, REGLAS, usar_semgrep=False)
        obj_c = ObjetivoEjecucion(base_url=config.base_url_corregido, tokens_prueba=OBJETIVO_PRUEBA)
        capa_c = VerificationLayer(objetivo=obj_c if obj_c.disponible else None)
        # Regresion: el propietario legitimo debe seguir viendo su pedido.
        estado_reg, cuerpo_reg = _get(f"{config.base_url_corregido}/api/orders/ord-1",
                                      {"Authorization": "Bearer token-ana"})
        regresion_ok = estado_reg == 200 and "ord-1" in cuerpo_reg
        for rf in confirmados:
            f = rf.finding
            redetectado = any(h.rule_id == f.rule_id and h.archivo == f.archivo for h in hallazgos_c)
            poc = capa_c.verify(f, rf.triaje) if rf.triaje else None
            poc_confirma = bool(poc and poc.intentada and poc.explotabilidad_confirmada)
            validado = (not poc_confirma) and regresion_ok and bool(poc and poc.intentada)
            fix = {
                "id": f.id, "rule_id": f.rule_id, "archivo": f.archivo,
                "redetectado": redetectado,
                "poc_tras_fix": None if poc is None else poc.model_dump(mode="json"),
                "regresion": {"peticion": "GET /api/orders/ord-1 como token-ana",
                              "estado": estado_reg, "ok": regresion_ok},
                "validado": validado,
            }
            fixes.append(fix)
            ev("fix", **fix)
        tiempos["validacion_fix_s"] = time.perf_counter() - t0
        ev("capa", capa=4, estado="fin", ms=round(tiempos["validacion_fix_s"] * 1000))

    # -- Metricas ------------------------------------------------------------
    evaluacion = evaluar(revisados, gt)
    configuraciones = [_confusion("SAST solo", "sast", evaluacion.sast_solo)]
    ev_base = None
    if config.modo == "baseline" or (capa is not None and not capa.usar_ia):
        configuraciones.append(_confusion("Pipeline sin IA", "baseline", evaluacion.pipeline))
    elif config.modo == "llm":
        verif_base = _verificar(capa_v, findings, triajes_base, verificaciones)
        ev_base = evaluar(_ensamblar(findings, triajes_base, verif_base), gt)
        configuraciones.append(_confusion("Pipeline sin IA", "baseline", ev_base.pipeline))
        configuraciones.append(_confusion(f"Pipeline + IA ({capa.etiqueta})", "llm", evaluacion.pipeline))

    reduccion = (100.0 * evaluacion.reduccion_fp / evaluacion.sast_solo.fp) if evaluacion.sast_solo.fp else 0.0
    metricas = {
        "pipeline_precision": round(evaluacion.pipeline.precision, 3),
        "pipeline_recall": round(evaluacion.pipeline.recall, 3),
        "pipeline_f1": round(evaluacion.pipeline.f1, 3),
        "fp_sast": evaluacion.sast_solo.fp,
        "fp_pipeline": evaluacion.pipeline.fp,
        "reduccion_fp_pct": round(reduccion, 1),
        "confirmados_poc": evaluacion.confirmados_por_poc,
        "falsas_confirmaciones": evaluacion.falsas_confirmaciones,
        "tp_explotables": evaluacion.tp_explotables_totales,
        "explotabilidad_pct": round(evaluacion.pct_explotabilidad_confirmada, 1)
        if evaluacion.tp_explotables_totales else None,
        # Solo tiene sentido medir la latencia del triaje cuando lo hizo un LLM.
        "triaje_medio_s": round(sum(tiempos_triaje) / len(tiempos_triaje), 2)
        if (tiempos_triaje and capa is not None and capa.usar_ia) else None,
        "fixes_validados_pct": round(100.0 * sum(f["validado"] for f in fixes) / len(fixes), 1) if fixes else None,
        "tokens_entrada": capa.uso.entrada if capa else 0,
        "tokens_salida": capa.uso.salida if capa else 0,
        "duracion_s": round(time.perf_counter() - inicio, 2),
        "sin_etiqueta": evaluacion.sin_etiqueta,
    }
    if config.modo == "sast":
        # Sin triaje el "pipeline" es el SAST: no hay reduccion que medir.
        metricas["reduccion_fp_pct"] = 0.0
    criterios = evaluar_criterios(metricas, esc.id) if config.modo != "sast" else []
    ev("metricas", configuraciones=configuraciones, metricas=metricas, criterios=criterios)

    comparacion = []
    for rf in revisados:
        f = rf.finding
        etiqueta = gt.lookup(f.rule_id, f.archivo)
        comparacion.append({
            "id": f.id, "rule_id": f.rule_id, "titulo": f.titulo, "cwe": f.cwe,
            "archivo": f.archivo, "linea": f.linea, "severidad": f.severidad.value,
            "real": None if etiqueta is None else etiqueta.etiqueta,
            "explotable": None if etiqueta is None else etiqueta.explotable,
            "nota": None if etiqueta is None else etiqueta.nota,
            "baseline": triajes_base[f.id].veredicto,
            "llm": triajes[f.id].veredicto if (config.modo == "llm" and capa and capa.usar_ia) else None,
            "estado": rf.estado.value,
        })

    # -- Reporte -------------------------------------------------------------
    salida = SALIDA_WEB / id_ejec
    reporte = PipelineReport(
        objetivo=esc.raiz.relative_to(REPO).as_posix(),
        generado_en=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        modelo_triaje=etiqueta_triaje if (capa and capa.usar_ia) else None,
        hallazgos=revisados,
        duracion_segundos=metricas["duracion_s"],
        tokens_entrada=metricas["tokens_entrada"],
        tokens_salida=metricas["tokens_salida"],
    )
    escribir_reportes(reporte, salida, formatear(evaluacion))

    resultado = {
        "id": id_ejec,
        "generado_en": reporte.generado_en,
        "escenario": esc.resumen(),
        "modo": config.modo,
        "triaje": etiqueta_triaje,
        "banco": config.base_url if objetivo else None,
        "tiempos": {k: round(v, 3) for k, v in tiempos.items()},
        "configuraciones": configuraciones,
        "metricas": metricas,
        "criterios": criterios,
        "comparacion": comparacion,
        "fixes": fixes,
        "reporte": json.loads(reporte.model_dump_json()),
    }
    (salida / "resultado.json").write_text(json.dumps(resultado, ensure_ascii=False, indent=2), encoding="utf-8")
    ev("fin", id=id_ejec, duracion_s=metricas["duracion_s"])
    return resultado


def listar_ejecuciones() -> list[dict]:
    if not SALIDA_WEB.exists():
        return []
    out = []
    for p in sorted(SALIDA_WEB.glob("*/resultado.json"), reverse=True):
        try:
            r = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append({
            "id": r["id"], "generado_en": r["generado_en"], "escenario": r["escenario"]["id"],
            "modo": r["modo"], "triaje": r["triaje"], "configuraciones": r["configuraciones"],
            "metricas": r["metricas"], "criterios": r["criterios"],
        })
    return out


def cargar_ejecucion(id_ejec: str) -> dict | None:
    p = SALIDA_WEB / Path(id_ejec).name / "resultado.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
