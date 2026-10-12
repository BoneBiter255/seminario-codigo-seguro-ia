"use strict";

// ====================================================================== util
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const corto = (rule) => rule.replace(/^java\.(spring\.)?/, "");
const nombreArchivo = (p) => p.split("/").pop();
const fmtSeg = (ms) => (ms == null ? "—" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);
const fmt2 = (v) => (v == null ? "—" : Number(v).toFixed(2));

async function api(ruta, opciones) {
  const r = await fetch(ruta, opciones);
  const tipo = r.headers.get("Content-Type") || "";
  const datos = tipo.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((datos && datos.error) || `HTTP ${r.status}`);
  return datos;
}
const post = (ruta, cuerpo) => api(ruta, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cuerpo) });

const ESTADOS = {
  CONFIRMADO_EXPLOTABLE: ["critico", "⚡", "Confirmado explotable"],
  PROBABLE_NO_VERIFICADO: ["serio", "▲", "Probable, sin PoC"],
  REFUTADO_POR_POC: ["bien", "✓", "Refutado por PoC"],
  DESCARTADO_FALSO_POSITIVO: ["", "○", "Descartado (ruido)"],
  SIN_TRIAJE: ["", "·", "Sin triaje"],
};
const VEREDICTOS = {
  verdadero_positivo: ["critico", "●", "Real"],
  falso_positivo: ["bien", "○", "Ruido"],
  incierto: ["aviso", "?", "Incierto"],
};
const SEV = { CRITICAL: "CRÍT", HIGH: "ALTA", MEDIUM: "MEDIA", LOW: "BAJA", INFO: "INFO" };
const chip = ([clase, icono, texto], extra = "") =>
  `<span class="chip ${clase} ${extra}"><span class="ic" aria-hidden="true">${icono}</span>${esc(texto)}</span>`;

// ================================================================== pestañas
function irA(tab) {
  $$(".pestanas button").forEach((b) => b.classList.toggle("activa", b.dataset.tab === tab));
  $$(".tab").forEach((t) => t.classList.toggle("activa", t.id === `tab-${tab}`));
  try { localStorage.setItem("revia-tab", tab); } catch (_) { /* sin almacenamiento */ }
}
$$(".pestanas button").forEach((b) => b.addEventListener("click", () => irA(b.dataset.tab)));

// ==================================================================== estado
let ESTADO = null;

async function cargarEstado() {
  ESTADO = await api("/api/estado");
  const p = ESTADO.proveedores;
  const ind = [];
  ind.push(`<span class="ind ${ESTADO.bancos.vulnerable ? "ok" : "no"}" title="${esc(ESTADO.bancos.vulnerable)}"><span class="pt"></span>Banco vulnerable</span>`);
  ind.push(`<span class="ind ${ESTADO.bancos.corregido ? "ok" : "no"}" title="${esc(ESTADO.bancos.corregido)}"><span class="pt"></span>Banco corregido</span>`);
  const llms = Object.entries(p).filter(([, v]) => v.disponible).map(([k]) => k);
  ind.push(`<span class="ind ${llms.length ? "ok" : "no"}"><span class="pt"></span>LLM: ${llms.length ? esc(llms.join(", ")) : "no disponible"}</span>`);
  $("#indicadores").innerHTML = ind.join("");

  $("#sel-escenario").innerHTML = ESTADO.escenarios.map((e) => `<option value="${e.id}">${esc(e.nombre)}</option>`).join("");
  const provs = Object.entries(p).filter(([, v]) => v.disponible);
  $("#sel-proveedor").innerHTML = provs.length
    ? provs.map(([k]) => `<option value="${k}">${k}</option>`).join("")
    : `<option value="auto">ninguno disponible</option>`;
  actualizarModelos();
  renderPruebas();
}

function actualizarModelos() {
  const prov = $("#sel-proveedor").value;
  const info = ESTADO.proveedores[prov];
  let modelos = [];
  if (info) modelos = prov === "ollama" && info.modelos.length ? info.modelos : [info.por_defecto];
  $("#sel-modelo").innerHTML = modelos.map((m) => `<option ${m === info?.por_defecto ? "selected" : ""}>${esc(m)}</option>`).join("") || "<option value=''>—</option>";
  const llm = $("#sel-modo").value === "llm";
  $("#sel-proveedor").disabled = !llm;
  $("#sel-modelo").disabled = !llm;
  $("#sel-razonamiento").disabled = !llm || prov !== "ollama";
}
$("#sel-proveedor").addEventListener("change", actualizarModelos);
$("#sel-modo").addEventListener("change", actualizarModelos);

// ================================================================ escenarios
const PII = /(Bruno|bruno@example\.com|CC-8070605040|\+57 301 444 5566|u-2002)/g;

function juzgar(caso, estado) {
  const tipo = ESTADO.pruebas[caso].tipo;
  if (tipo === "ataque") return estado === 200 ? ["critico", "✗", `${estado} · datos de otro usuario`] : ["bien", "✓", `${estado} · bloqueado`];
  if (tipo === "control") return estado === 401 ? ["bien", "✓", `${estado} · sin sesión`] : ["critico", "✗", String(estado)];
  return estado === 200 ? ["bien", "✓", `${estado} · permitido`] : ["critico", "✗", `${estado} · roto`];
}

function renderPruebas() {
  const filas = Object.entries(ESTADO.pruebas).map(([id, p]) => `
    <tr data-caso="${id}">
      <td><b>${esc(p.titulo)}</b><br><code>GET ${esc(p.ruta)}</code></td>
      <td>${p.tipo === "ataque" ? chip(["critico", "!", "intento indebido"]) : p.tipo === "control" ? chip(["", "·", "control"]) : chip(["bien", "✓", "uso normal"])}</td>
      <td class="ayuda">${esc(p.esperado)}</td>
      <td data-esc="vulnerable" class="click">—</td>
      <td data-esc="corregido" class="click">—</td>
    </tr>`).join("");
  $("#tabla-pruebas tbody").innerHTML = filas;
}

const RESPUESTAS = {};
async function correrPruebas() {
  const btn = $("#btn-pruebas");
  btn.disabled = true;
  for (const caso of Object.keys(ESTADO.pruebas)) {
    for (const escenario of ["vulnerable", "corregido"]) {
      const r = await post("/api/prueba", { caso, escenario });
      RESPUESTAS[`${caso}|${escenario}`] = r;
      const celda = $(`#tabla-pruebas tr[data-caso="${caso}"] td[data-esc="${escenario}"]`);
      celda.innerHTML = chip(juzgar(caso, r.estado));
      celda.title = "Ver la respuesta completa";
    }
  }
  btn.disabled = false;
  mostrarRespuesta("ajeno");
}
$("#btn-pruebas").addEventListener("click", correrPruebas);
$("#tabla-pruebas").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-caso]");
  if (tr) mostrarRespuesta(tr.dataset.caso);
});

function jsonResaltado(obj) {
  return esc(JSON.stringify(obj, null, 2)).replace(PII, '<span class="pii">$1</span>');
}

function mostrarRespuesta(caso) {
  const lados = ["vulnerable", "corregido"].map((esc_) => {
    const r = RESPUESTAS[`${caso}|${esc_}`];
    if (!r) return "";
    const cab = Object.entries(r.cabeceras).map(([k, v]) => `${k}: ${v}`).join("\n") || "(sin cabeceras)";
    return `<div><h3>Banco ${esc_} — HTTP ${r.estado} ${chip(juzgar(caso, r.estado))}</h3>
      <pre class="json">GET ${esc(r.url)}\n${esc(cab)}</pre>
      <pre class="json">${r.cuerpo === "" || r.cuerpo == null ? "(sin cuerpo)" : jsonResaltado(r.cuerpo)}</pre></div>`;
  });
  $("#detalle-prueba").innerHTML = `<h2>${esc(ESTADO.pruebas[caso].titulo)}</h2>
    <p class="ayuda">Resaltado: datos personales de Bruno (otro usuario).</p><div class="resp">${lados.join("")}</div>`;
}

// tráfico de los bancos
let traficoVisto = 0;
async function sondearTrafico() {
  try {
    const t = await api(`/api/trafico?desde=${traficoVisto}`);
    if (t.total < traficoVisto) traficoVisto = 0;
    const cuerpo = $("#tabla-trafico tbody");
    for (const e of t.entradas) {
      const cred = e.autorizacion ? e.autorizacion.replace("Bearer ", "") : Object.keys(e.cabeceras_internas).length ? Object.entries(e.cabeceras_internas).map(([k, v]) => `${k}: ${v}`).join(", ") : "—";
      const tr = document.createElement("tr");
      tr.className = "nuevo";
      tr.innerHTML = `<td class="mono">${esc(e.hora)}</td><td>${esc(e.modo)}</td><td class="mono">${esc(e.metodo)} ${esc(e.ruta)}</td><td class="mono">${esc(cred)}</td><td class="num-col"><b>${e.estado}</b></td>`;
      cuerpo.prepend(tr);
    }
    while (cuerpo.children.length > 200) cuerpo.lastChild.remove();
    traficoVisto = t.total;
  } catch (_) { /* servidor reiniciándose */ }
}

async function cargarDiff() {
  const d = await api("/api/diff");
  $("#diff").innerHTML = d.map((f) => `<h3 class="mono">${esc(f.archivo)}</h3><pre class="json">${f.diff.split("\n").map((l) => {
    const c = l.startsWith("+++") || l.startsWith("---") || l.startsWith("@@") ? "diff-hdr" : l.startsWith("+") ? "diff-add" : l.startsWith("-") ? "diff-del" : "";
    return c ? `<span class="${c}">${esc(l)}</span>` : esc(l) + "\n";
  }).join("")}</pre>`).join("");
}

// ================================================================== análisis
const RUN = { hallazgos: {}, triajes: {}, prompts: {}, verif: {}, estados: {}, fixes: {}, reales: {}, ms: {}, promptSistema: null, etiqueta: null, escenario: null, modo: null, seleccionado: null, manual: false, visto: 0, sondeo: null };

function resetRun() {
  Object.assign(RUN, { hallazgos: {}, triajes: {}, prompts: {}, verif: {}, estados: {}, fixes: {}, reales: {}, ms: {}, promptSistema: null, etiqueta: null, seleccionado: null, manual: false, visto: 0 });
  $("#tabla-hallazgos tbody").innerHTML = "";
  $("#avisos").innerHTML = "";
  $("#resumen-hallazgos").textContent = "";
  $$(".etapa").forEach((e) => { e.classList.remove("activa", "hecha"); $("[data-info]", e).textContent = "—"; });
  $$("#diagrama .nodo").forEach((n) => n.classList.remove("activo", "hecho"));
  ["n-c1", "n-c2", "n-c3", "n-rep"].forEach((id) => { $(`#${id}`).textContent = ""; });
  $("#n-c4").textContent = "banco corregido + regresión";
  $("#panel-detalle").innerHTML = `<h2>Detalle del hallazgo</h2><p class="ayuda">Selecciona un hallazgo para ver qué recibió la IA, qué respondió y qué demostró la PoC.</p>`;
}

async function ejecutarAnalisis() {
  const cuerpo = {
    escenario: $("#sel-escenario").value,
    modo: $("#sel-modo").value,
    proveedor: $("#sel-proveedor").value,
    modelo: $("#sel-modelo").value,
    razonamiento: $("#sel-razonamiento").value,
  };
  try {
    await post("/api/ejecuciones", cuerpo);
  } catch (e) {
    $("#avisos").innerHTML = `<div class="aviso-box error">${esc(e.message)}</div>`;
    return;
  }
  resetRun();
  RUN.envivo = true;
  $("#btn-ejecutar").disabled = true;
  $("#btn-ejecutar").textContent = "Analizando…";
  sondearCorrida();
}
$("#btn-ejecutar").addEventListener("click", ejecutarAnalisis);

async function sondearCorrida() {
  clearTimeout(RUN.sondeo);
  let c;
  try { c = await api(`/api/corrida?desde=${RUN.visto}`); } catch (_) { RUN.sondeo = setTimeout(sondearCorrida, 800); return; }
  if (!c.existe) return;
  for (const e of c.eventos) procesar(e);
  RUN.visto += c.eventos.length;
  if (c.terminado && !c.eventos.length) {
    $("#btn-ejecutar").disabled = false;
    $("#btn-ejecutar").textContent = "▶ Ejecutar análisis";
    return;
  }
  RUN.sondeo = setTimeout(sondearCorrida, 350);
}

const NODO_CAPA = { 1: "c1", 2: "c2", 3: "c3", 4: "c4" };

function etapa(n, clase, info) {
  const e = $(`.etapa[data-capa="${n}"]`);
  if (clase === "activa") { e.classList.add("activa"); e.classList.remove("hecha"); }
  if (clase === "hecha") { e.classList.remove("activa"); e.classList.add("hecha"); }
  if (info != null) $("[data-info]", e).textContent = info;
}
function nodo(id, clase) {
  const n = $(`#diagrama .nodo[data-nodo="${id}"]`);
  if (!n) return;
  n.classList.toggle("activo", clase === "activo");
  n.classList.toggle("hecho", clase === "hecho");
}

function procesar(e) {
  switch (e.tipo) {
    case "inicio":
      RUN.escenario = e.escenario.id;
      RUN.modo = e.modo;
      nodo("codigo", "hecho");
      break;
    case "capa": {
      const n = e.capa;
      if (e.estado === "inicio") {
        etapa(n, "activa", "en curso…");
        nodo(NODO_CAPA[n], "activo");
        if (n === 3) nodo("banco", "activo");
        if (n === 4) nodo("banco", "activo");
      } else {
        const info = n === 1 ? `${e.total} hallazgos · ${fmtSeg(e.ms)}` : n === 2 ? `${Object.keys(RUN.triajes).length} triados · ${fmtSeg(e.ms)}` : n === 3 ? `${Object.values(RUN.verif).filter((v) => v.intentada).length} PoC · ${fmtSeg(e.ms)}` : `${Object.values(RUN.fixes).filter((f) => f.validado).length}/${Object.keys(RUN.fixes).length} fixes validados`;
        etapa(n, "hecha", info);
        nodo(NODO_CAPA[n], "hecho");
        if (n >= 3) nodo("banco", "hecho");
        if (n === 1) $("#n-c1").textContent = `${e.total} hallazgos`;
        if (n === 3) $("#n-c3").textContent = `${Object.values(RUN.verif).filter((v) => v.explotabilidad_confirmada).length} confirmados`;
        if (n === 4) $("#n-c4").textContent = info;
      }
      break;
    }
    case "hallazgo":
      RUN.hallazgos[e.hallazgo.id] = e.hallazgo;
      RUN.reales[e.hallazgo.id] = e.real;
      agregarFila(e.hallazgo);
      break;
    case "triaje_config":
      RUN.promptSistema = e.prompt_sistema;
      RUN.etiqueta = e.etiqueta;
      $("#n-modelo").textContent = e.usar_ia ? e.etiqueta.replace(/^ollama:/, "Ollama · ") : "sin IA (heurística)";
      break;
    case "triaje_inicio":
      RUN.prompts[e.id] = e.prompt;
      celda(e.id, "ia", chip(["ia", "⟳", e.prompt ? "la IA está leyendo…" : "evaluando…"], "girando"));
      etapa(2, null, `${e.n}/${e.total} · ${corto(RUN.hallazgos[e.id].rule_id)}`);
      $("#n-c2").textContent = `${e.n}/${e.total}`;
      if (!RUN.manual) seleccionar(e.id, false);
      break;
    case "triaje_fin":
      RUN.triajes[e.id] = e.veredicto;
      RUN.ms[e.id] = e.ms;
      celda(e.id, "ia", chip(VEREDICTOS[e.veredicto.veredicto]) + (e.degradado ? ' <span class="chip aviso" title="El LLM falló y se usó la heurística">degradado</span>' : ""));
      celda(e.id, "conf", `<span class="barra-conf"><i style="width:${Math.round(e.veredicto.confianza * 100)}%"></i></span>${fmt2(e.veredicto.confianza)}`);
      celda(e.id, "ms", fmtSeg(e.ms));
      if (RUN.seleccionado === e.id) renderDetalle(e.id);
      break;
    case "verificacion":
      RUN.verif[e.id] = e.resultado;
      celda(e.id, "poc", pocChip(e.resultado));
      if (RUN.seleccionado === e.id) renderDetalle(e.id);
      break;
    case "estado":
      RUN.estados[e.id] = e.estado;
      celda(e.id, "estado", chip(ESTADOS[e.estado]));
      break;
    case "fix":
      RUN.fixes[e.id] = e;
      etapa(4, null, `${Object.values(RUN.fixes).filter((f) => f.validado).length} validados`);
      break;
    case "metricas": {
      etapa(5, "hecha", e.metricas.pipeline_f1 != null ? `F1 ${fmt2(e.metricas.pipeline_f1)} · ${e.criterios.filter((c) => c.cumple).length}/${e.criterios.length} criterios` : "listo");
      nodo("reporte", "hecho");
      $("#n-rep").textContent = `F1 ${fmt2(e.metricas.pipeline_f1)}`;
      const est = Object.values(RUN.estados);
      $("#resumen-hallazgos").textContent = `${est.length} hallazgos · ${est.filter((s) => s === "CONFIRMADO_EXPLOTABLE").length} confirmados · ${est.filter((s) => s === "DESCARTADO_FALSO_POSITIVO").length} descartados`;
      break;
    }
    case "fin":
      $("#avisos").innerHTML += `<div class="aviso-box">Análisis terminado en ${e.duracion_s.toFixed(1)} s. <a href="#" id="ir-metricas">Ver métricas →</a></div>`;
      $("#ir-metricas").addEventListener("click", (ev) => { ev.preventDefault(); irA("metricas"); });
      // Solo se salta a la nueva ejecución si se vio en vivo; al recargar la
      // página se respeta la ejecución elegida.
      if (RUN.envivo) cargarEjecuciones(e.id);
      RUN.envivo = false;
      break;
    case "aviso":
      $("#avisos").innerHTML += `<div class="aviso-box">${esc(e.mensaje)}</div>`;
      break;
    case "error":
      $("#avisos").innerHTML += `<div class="aviso-box error">Error: ${esc(e.mensaje)}</div>`;
      break;
  }
}

function pocChip(v) {
  if (!v.intentada) return `<span class="chip" title="${esc(v.motivo_omision)}">— sin PoC</span>`;
  const html = v.explotabilidad_confirmada ? chip(["critico", "⚡", "confirmada"]) : chip(["bien", "✓", "refutada"]);
  return `<span title="HTTP ${v.codigo_salida} · ${esc(v.poc_ruta || "")}">${html}</span>`;
}

function agregarFila(f) {
  const cuerpo = $("#tabla-hallazgos tbody");
  $(".vacio", cuerpo)?.remove();
  const tr = document.createElement("tr");
  tr.className = "click nuevo";
  tr.dataset.id = f.id;
  tr.innerHTML = `<td><span class="sev ${f.severidad}">${SEV[f.severidad] || f.severidad}</span></td>
    <td>${esc(corto(f.rule_id))}<br><span class="ayuda mono">${esc(f.cwe)}</span></td><td class="mono" title="${esc(f.archivo)}">${esc(nombreArchivo(f.archivo))}:${f.linea}</td>
    <td data-c="ia">${RUN.modo === "sast" ? '<span class="ayuda">sin triaje</span>' : '<span class="ayuda">en cola</span>'}</td><td data-c="conf"></td><td data-c="ms" class="num-col"></td><td data-c="poc"></td><td data-c="estado"></td>`;
  cuerpo.append(tr);
}
function celda(id, c, html) {
  const td = $(`#tabla-hallazgos tr[data-id="${id}"] td[data-c="${c}"]`);
  if (td) td.innerHTML = html;
}
$("#tabla-hallazgos").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-id]");
  if (tr) seleccionar(tr.dataset.id, true);
});

function seleccionar(id, manual) {
  if (manual) RUN.manual = true;
  RUN.seleccionado = id;
  $$("#tabla-hallazgos tr").forEach((t) => t.classList.toggle("sel", t.dataset.id === id));
  renderDetalle(id);
}

const CACHE_CODIGO = {};
async function codigo(escenario, archivo) {
  const k = `${escenario}|${archivo}`;
  if (!(k in CACHE_CODIGO)) CACHE_CODIGO[k] = await api(`/api/codigo?escenario=${encodeURIComponent(escenario)}&archivo=${encodeURIComponent(archivo)}`);
  return CACHE_CODIGO[k];
}

async function renderDetalle(id) {
  const f = RUN.hallazgos[id];
  if (!f) return;
  const t = RUN.triajes[id];
  const v = RUN.verif[id];
  const fx = RUN.fixes[id];
  const prompt = RUN.prompts[id];
  const real = RUN.reales[id];
  const usarIA = !!RUN.promptSistema;

  let iaHtml;
  if (RUN.modo === "sast") {
    iaHtml = `<p class="ayuda">Modo solo SAST: este hallazgo no pasa por triaje.</p>`;
  } else {
    const entrada = usarIA
      ? `<details ${t ? "" : "open"}><summary>Entrada al modelo (prompt del hallazgo)</summary><pre class="prompt">${esc(prompt || "")}</pre></details>
         <details><summary>Instrucciones de sistema (iguales para todos los hallazgos)</summary><pre class="prompt">${esc(RUN.promptSistema)}</pre></details>`
      : `<p class="ayuda">Triaje sin IA: decide solo por el «ruido esperado» de la regla (<b>${esc(f.ruido_esperado)}</b>). No lee el código.</p>`;
    const salida = t
      ? `<dl class="kv">
          <dt>Veredicto</dt><dd>${chip(VEREDICTOS[t.veredicto])} · confianza ${fmt2(t.confianza)} · ${esc(t.prioridad)} · ${fmtSeg(RUN.ms[id])}</dd>
          <dt>Razonamiento</dt><dd>${esc(t.razonamiento)}</dd>
          <dt>Impacto</dt><dd>${esc(t.impacto)}</dd>
          <dt>Estrategia PoC</dt><dd>${esc(t.estrategia_poc)}</dd>
          <dt>Corrección</dt><dd>${esc(t.correccion_sugerida)}</dd>
        </dl>
        <details><summary>JSON devuelto (validado con el esquema TriageVerdict)</summary><pre class="json">${esc(JSON.stringify(t, null, 2))}</pre></details>`
      : chip(["ia", "⟳", "esperando la respuesta…"], "girando");
    iaHtml = `${entrada}<h3 style="margin-top:10px">Salida ${usarIA ? "del modelo" : "de la heurística"}</h3>${salida}`;
  }

  const verifHtml = v
    ? (v.intentada
      ? `<p>${pocChip(v)} <code>${esc(v.poc_ruta || "")}</code></p><pre class="json">${esc(v.evidencia)}</pre>`
      : `<p class="ayuda">${esc(v.motivo_omision)}</p>`)
    : `<p class="ayuda">${t && t.veredicto === "falso_positivo" ? "El triaje lo descartó: no se gasta una PoC." : RUN.modo === "sast" ? "—" : "Pendiente."}</p>`;

  const fixHtml = fx
    ? `<div class="bloque"><h3>4 · Validación del fix</h3><dl class="kv">
        <dt>Re-escaneo</dt><dd>${fx.redetectado ? "la regla sigue disparándose en el código corregido" : "la regla ya no se dispara en el código corregido"}</dd>
        <dt>PoC tras el fix</dt><dd>${fx.poc_tras_fix ? pocChip(fx.poc_tras_fix) : "—"}</dd>
        <dt>Regresión</dt><dd>${esc(fx.regresion.peticion)} → HTTP ${fx.regresion.estado} ${fx.regresion.ok ? chip(["bien", "✓", "sigue funcionando"]) : chip(["critico", "✗", "roto"])}</dd>
        <dt>Resultado</dt><dd>${fx.validado ? chip(["bien", "✓", "fix validado"]) : chip(["critico", "✗", "fix no validado"])}</dd></dl></div>`
    : "";

  $("#panel-detalle").innerHTML = `
    <h2>${esc(f.titulo)}</h2>
    <p><span class="sev ${f.severidad}">${f.severidad}</span> <code>${esc(f.cwe)}</code> <code>${esc(f.rule_id)}</code></p>
    <p class="mono ayuda">${esc(f.archivo)}:${f.linea}</p>
    <div class="bloque"><h3>1 · Lo que vio la regla</h3><p>${esc(f.mensaje)}</p><div id="vista-codigo"><p class="ayuda">Cargando código…</p></div></div>
    <div class="bloque ${usarIA ? "ia" : ""}"><h3>2 · Triaje ${usarIA ? `con IA <span class="chip ia">${esc(RUN.etiqueta)}</span>` : "sin IA"}</h3>${iaHtml}</div>
    <div class="bloque"><h3>3 · Verificación independiente</h3>${verifHtml}</div>
    ${fixHtml}
    <div class="bloque"><h3>Resultado</h3><dl class="kv">
      <dt>Estado final</dt><dd>${RUN.estados[id] ? chip(ESTADOS[RUN.estados[id]]) : "—"}</dd>
      <dt>Verdad de terreno</dt><dd>${real == null ? "sin etiqueta" : real === "verdadero_positivo" ? "vulnerabilidad real" : "falso positivo"} <span class="ayuda">(etiqueta humana del dataset, solo para medir)</span></dd></dl></div>`;

  try {
    const src = await codigo(RUN.escenario, f.archivo);
    if (RUN.seleccionado !== id) return;
    const lineas = src.split(/\r?\n/);
    const ini = Math.max(0, f.linea - 9), fin = Math.min(lineas.length, f.linea + 12);
    const html = lineas.slice(ini, fin).map((l, i) => {
      const n = ini + i + 1;
      return `<span class="ln ${n === f.linea ? "hl" : ""}"><span class="n">${n}</span>${esc(l)}</span>`;
    }).join("");
    $("#vista-codigo").innerHTML = `<pre class="codigo">${html}</pre>`;
  } catch (_) {
    $("#vista-codigo").innerHTML = `<pre class="json">${esc(f.fragmento)}</pre>`;
  }
}

// ================================================================== métricas
let EJECUCIONES = [];
let ACTUAL = null;

async function cargarEjecuciones(seleccionar_) {
  EJECUCIONES = await api("/api/ejecuciones");
  const sel = $("#sel-ejecucion");
  const etiquetaModo = { sast: "solo SAST", baseline: "sin IA", llm: "con IA" };
  sel.innerHTML = EJECUCIONES.map((e) => `<option value="${e.id}">${esc(e.generado_en)} · ${esc(e.escenario)} · ${esc(etiquetaModo[e.modo])}${e.triaje && e.modo === "llm" ? " · " + esc(e.triaje) : ""}</option>`).join("");
  if (!EJECUCIONES.length) return;
  sel.value = seleccionar_ && EJECUCIONES.some((e) => e.id === seleccionar_) ? seleccionar_ : EJECUCIONES[0].id;
  await mostrarEjecucion(sel.value);
}
$("#sel-ejecucion").addEventListener("change", (e) => mostrarEjecucion(e.target.value));

const tooltip = document.createElement("div");
tooltip.className = "tooltip";
document.body.append(tooltip);
function conTooltip(raiz) {
  raiz.addEventListener("mousemove", (e) => {
    const m = e.target.closest("[data-tip]");
    if (!m) { tooltip.style.display = "none"; return; }
    tooltip.innerHTML = m.dataset.tip;
    tooltip.style.display = "block";
    tooltip.style.left = `${e.clientX + 14}px`;
    tooltip.style.top = `${e.clientY + 14}px`;
  });
  raiz.addEventListener("mouseleave", () => { tooltip.style.display = "none"; });
}

const SERIES = { sast: "var(--serie-1)", baseline: "var(--serie-2)", llm: "var(--serie-3)" };

function graficoBarrasAgrupadas(configs) {
  const cats = [["precision", "Precisión"], ["recall", "Recall"], ["f1", "F1"]];
  const W = 560, H = 260, m = { t: 16, r: 10, b: 30, l: 34 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const grupo = iw / cats.length, pad = 26, n = configs.length;
  const bw = Math.min(46, (grupo - pad) / n - 2);
  const y = (v) => m.t + ih - v * ih;
  let s = "";
  for (const g of [0, 0.25, 0.5, 0.75, 1]) s += `<line class="grid" x1="${m.l}" x2="${W - m.r}" y1="${y(g)}" y2="${y(g)}"/><text x="${m.l - 6}" y="${y(g) + 4}" text-anchor="end">${g.toFixed(2)}</text>`;
  cats.forEach(([k, nombre], gi) => {
    const x0 = m.l + gi * grupo + (grupo - (n * (bw + 2))) / 2;
    configs.forEach((c, i) => {
      const v = c[k], x = x0 + i * (bw + 2), h = Math.max(0, ih * v);
      const r = Math.min(4, h / 2);
      // barra con extremo redondeado de 4px y base recta
      s += `<path class="m" fill="${SERIES[c.id]}" d="M${x},${y(0)} V${y(v) + r} Q${x},${y(v)} ${x + r},${y(v)} H${x + bw - r} Q${x + bw},${y(v)} ${x + bw},${y(v) + r} V${y(0)} Z"
        data-tip="<b>${esc(c.nombre)}</b><br>${nombre}: ${v.toFixed(2)}"/>`;
      s += `<text class="val" x="${x + bw / 2}" y="${y(v) - 4}" text-anchor="middle">${v.toFixed(2)}</text>`;
    });
    s += `<text class="cat" x="${m.l + gi * grupo + grupo / 2}" y="${H - 8}" text-anchor="middle">${nombre}</text>`;
  });
  s += `<line class="eje" x1="${m.l}" x2="${W - m.r}" y1="${y(0)}" y2="${y(0)}"/>`;
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Precisión, recall y F1 por configuración">${s}</svg>`;
}

function graficoFP(configs) {
  const W = 560, filaH = 34, m = { t: 6, r: 40, b: 6, l: 190 };
  const H = m.t + m.b + configs.length * filaH;
  const max = Math.max(1, ...configs.map((c) => c.fp));
  const iw = W - m.l - m.r;
  let s = "";
  configs.forEach((c, i) => {
    const yb = m.t + i * filaH + 7, w = (c.fp / max) * iw, h = filaH - 14, r = Math.min(4, w / 2);
    s += `<text class="cat" x="${m.l - 8}" y="${yb + h / 2 + 4}" text-anchor="end">${esc(c.nombre.length > 28 ? c.nombre.slice(0, 27) + "…" : c.nombre)}</text>`;
    if (w > 0) s += `<path class="m" fill="var(--serie-1)" d="M${m.l},${yb} H${m.l + w - r} Q${m.l + w},${yb} ${m.l + w},${yb + r} V${yb + h - r} Q${m.l + w},${yb + h} ${m.l + w - r},${yb + h} H${m.l} Z" data-tip="<b>${esc(c.nombre)}</b><br>Falsos positivos: ${c.fp}"/>`;
    s += `<text class="val" x="${m.l + w + 6}" y="${yb + h / 2 + 4}">${c.fp}</text>`;
  });
  s += `<line class="eje" x1="${m.l}" x2="${m.l}" y1="${m.t}" y2="${H - m.b}"/>`;
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Falsos positivos por configuración">${s}</svg>`;
}

function fmtCriterio(c) {
  if (c.valor == null) return "—";
  if (c.metrica.endsWith("_pct")) return `${Number(c.valor).toFixed(0)} %`;
  if (c.metrica.endsWith("_s")) return `${Number(c.valor).toFixed(1)} s`;
  if (Number.isInteger(c.valor)) return String(c.valor);
  return Number(c.valor).toFixed(2);
}

async function mostrarEjecucion(id) {
  const r = await api(`/api/ejecuciones/${encodeURIComponent(id)}`);
  ACTUAL = r;
  const m = r.metricas;
  $("#info-ejecucion").textContent = `Escenario ${r.escenario.nombre} · triaje: ${r.triaje || "ninguno (solo SAST)"} · ${m.duracion_s.toFixed(1)} s`;

  const criterios = r.criterios.length
    ? `<div class="criterios">${r.criterios.map((c) => `
        <div class="criterio ${c.cumple === true ? "cumple" : c.cumple === false ? "falla" : ""}">
          <div class="nombre">${esc(c.nombre)}</div>
          <div class="valor">${fmtCriterio(c)}</div>
          <div class="umbral">objetivo ${esc(c.operador)} ${esc(fmtCriterio({ ...c, valor: c.umbral }))}</div>
          <div>${c.cumple === true ? chip(["bien", "✓", "Cumple"]) : c.cumple === false ? chip(["critico", "✗", "No cumple"]) : chip(["", "·", "Sin dato"])}</div>
        </div>`).join("")}</div>`
    : "";

  const leyenda = `<div class="leyenda">${r.configuraciones.map((c) => `<span><i style="background:${SERIES[c.id]}"></i>${esc(c.nombre)}</span>`).join("")}</div>`;
  const tablaConf = `<div class="tabla-wrap"><table class="tabla"><thead><tr><th>Configuración</th><th class="num-col">TP</th><th class="num-col">FP</th><th class="num-col">FN</th><th class="num-col">TN</th><th class="num-col">Precisión</th><th class="num-col">Recall</th><th class="num-col">F1</th></tr></thead><tbody>
    ${r.configuraciones.map((c) => `<tr><td>${esc(c.nombre)}</td><td class="num-col">${c.tp}</td><td class="num-col">${c.fp}</td><td class="num-col">${c.fn}</td><td class="num-col">${c.tn}</td><td class="num-col">${fmt2(c.precision)}</td><td class="num-col">${fmt2(c.recall)}</td><td class="num-col"><b>${fmt2(c.f1)}</b></td></tr>`).join("")}</tbody></table></div>`;

  const t = r.tiempos;
  const tiempos = `<dl class="kv">
    <dt>Capa determinista</dt><dd>${fmtSeg(Math.round((t.determinista_s || 0) * 1000))}</dd>
    <dt>Triaje</dt><dd>${t.triaje_s != null ? fmtSeg(Math.round(t.triaje_s * 1000)) : "—"}${m.triaje_medio_s != null ? ` · ${m.triaje_medio_s.toFixed(2)} s por hallazgo` : ""}</dd>
    <dt>Verificación (PoC)</dt><dd>${t.verificacion_s != null ? fmtSeg(Math.round(t.verificacion_s * 1000)) : "—"}</dd>
    <dt>Validación del fix</dt><dd>${t.validacion_fix_s != null ? fmtSeg(Math.round(t.validacion_fix_s * 1000)) : "—"}</dd>
    <dt>Total</dt><dd><b>${m.duracion_s.toFixed(1)} s</b></dd>
    <dt>Tokens</dt><dd>${m.tokens_entrada.toLocaleString("es")} entrada · ${m.tokens_salida.toLocaleString("es")} salida</dd>
    <dt>Costo</dt><dd>${r.triaje && r.triaje.startsWith("ollama") ? "$0 (modelo local)" : r.modo === "llm" ? "según tarifa del proveedor" : "$0"}</dd>
    <dt>PoC</dt><dd>${m.confirmados_poc} confirmadas · ${m.falsas_confirmaciones} falsas confirmaciones${m.tp_explotables ? ` · ${m.explotabilidad_pct.toFixed(0)} % de los ${m.tp_explotables} explotables` : ""}</dd>
  </dl>`;

  const decide = (v) => (v == null ? null : v !== "falso_positivo");
  const okx = (emite, real) => {
    if (emite == null || real == null) return '<span class="ayuda">—</span>';
    const bien = emite === (real === "verdadero_positivo");
    return `<span class="ok-x ${bien ? "si" : "no"}">${bien ? "✓" : "✗"}</span>`;
  };
  const vchip = (v) => (v ? chip(VEREDICTOS[v]) : '<span class="ayuda">—</span>');
  const hayLLM = r.comparacion.some((c) => c.llm);
  const comparacion = `<div class="tabla-wrap"><table class="tabla"><thead><tr><th>Hallazgo</th><th>Ubicación</th><th>Verdad</th><th>SAST solo</th><th>Sin IA</th>${hayLLM ? "<th>Con IA</th>" : ""}<th>Estado final</th></tr></thead><tbody>
    ${r.comparacion.map((c) => `<tr title="${esc(c.nota || "")}"><td>${esc(corto(c.rule_id))}<br><span class="ayuda mono">${esc(c.cwe)}</span></td>
      <td class="mono">${esc(nombreArchivo(c.archivo))}:${c.linea}</td>
      <td>${c.real === "verdadero_positivo" ? "<b>real</b>" + (c.explotable ? " ⚡" : "") : c.real ? "ruido" : "—"}</td>
      <td>${okx(true, c.real)} reporta</td>
      <td>${okx(decide(c.baseline), c.real)} ${vchip(c.baseline)}</td>
      ${hayLLM ? `<td>${okx(decide(c.llm), c.real)} ${vchip(c.llm)}</td>` : ""}
      <td>${chip(ESTADOS[c.estado])}</td></tr>`).join("")}</tbody></table></div>
    <p class="ayuda">✓ = decisión correcta frente a la etiqueta humana · ⚡ = explotable en el banco. Pasa el cursor sobre una fila para ver la justificación de la etiqueta.</p>`;

  const fixes = r.fixes.length
    ? `<article class="tarjeta"><h2>Validación de los fixes</h2><div class="tabla-wrap"><table class="tabla"><thead><tr><th>Hallazgo</th><th>Re-escaneo</th><th>PoC contra el corregido</th><th>Regresión (uso legítimo)</th><th>Fix</th></tr></thead><tbody>
      ${r.fixes.map((f) => `<tr><td>${esc(corto(f.rule_id))}<br><span class="ayuda mono">${esc(nombreArchivo(f.archivo))}</span></td><td>${f.redetectado ? "regla aún se dispara" : "regla ya no se dispara"}</td><td>${f.poc_tras_fix ? pocChip(f.poc_tras_fix) : "—"}</td><td>HTTP ${f.regresion.estado} ${f.regresion.ok ? chip(["bien", "✓", "funciona"]) : chip(["critico", "✗", "roto"])}</td><td>${f.validado ? chip(["bien", "✓", "validado"]) : chip(["critico", "✗", "no validado"])}</td></tr>`).join("")}
      </tbody></table></div></article>`
    : "";

  const historial = `<div class="tabla-wrap alto"><table class="tabla compacta"><thead><tr><th>Fecha</th><th>Escenario</th><th>Triaje</th><th class="num-col">Precisión</th><th class="num-col">Recall</th><th class="num-col">F1</th><th class="num-col">FP</th><th class="num-col">Criterios</th><th class="num-col">Duración</th></tr></thead><tbody>
    ${EJECUCIONES.map((e) => `<tr class="click ${e.id === r.id ? "sel" : ""}" data-ej="${e.id}"><td>${esc(e.generado_en)}</td><td>${esc(e.escenario)}</td><td>${esc(e.modo === "sast" ? "solo SAST" : e.triaje || e.modo)}</td>
      <td class="num-col">${fmt2(e.metricas.pipeline_precision)}</td><td class="num-col">${fmt2(e.metricas.pipeline_recall)}</td><td class="num-col"><b>${fmt2(e.metricas.pipeline_f1)}</b></td><td class="num-col">${e.metricas.fp_pipeline}</td>
      <td class="num-col">${e.criterios.length ? `${e.criterios.filter((c) => c.cumple).length}/${e.criterios.length}` : "—"}</td><td class="num-col">${e.metricas.duracion_s.toFixed(1)} s</td></tr>`).join("")}</tbody></table></div>`;

  $("#metricas-contenido").innerHTML = `
    ${criterios}
    <div class="grid-2">
      <article class="tarjeta grafico"><h2>Precisión, recall y F1 frente a la verdad de terreno</h2>${leyenda}${graficoBarrasAgrupadas(r.configuraciones)}</article>
      <article class="tarjeta grafico"><h2>Falsos positivos que llegan a revisión humana</h2>${graficoFP(r.configuraciones)}<h3 style="margin-top:14px">Matriz de confusión</h3>${tablaConf}</article>
    </div>
    <div class="grid-2">
      <article class="tarjeta"><h2>Tiempo, costo y evidencia</h2>${tiempos}</article>
      <article class="tarjeta"><h2>Historial de ejecuciones</h2>${historial}</article>
    </div>
    ${fixes}
    <article class="tarjeta"><h2>Decisión por hallazgo: SAST vs. sin IA vs. con IA</h2>${comparacion}</article>`;
  $$("#metricas-contenido .grafico").forEach(conTooltip);
  $$("#metricas-contenido tr[data-ej]").forEach((tr) => tr.addEventListener("click", () => { $("#sel-ejecucion").value = tr.dataset.ej; mostrarEjecucion(tr.dataset.ej); }));
  cargarReporte(r.id);
}

// =================================================================== reporte
function markdown(md) {
  const lineas = md.split(/\r?\n/);
  let html = "", i = 0;
  const inline = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/\*([^*]+)\*/g, "<i>$1</i>");
  while (i < lineas.length) {
    const l = lineas[i];
    if (l.startsWith("```")) {
      const buf = [];
      i++;
      while (i < lineas.length && !lineas[i].startsWith("```")) buf.push(lineas[i++]);
      html += `<pre>${esc(buf.join("\n"))}</pre>`;
    } else if (/^#{1,3} /.test(l)) {
      const n = l.match(/^#+/)[0].length;
      html += `<h${n}>${inline(l.slice(n + 1))}</h${n}>`;
    } else if (l.startsWith("|")) {
      const filas = [];
      while (i < lineas.length && lineas[i].startsWith("|")) filas.push(lineas[i++]);
      i--;
      html += "<table>" + filas.filter((f) => !/^\|[-| ]+\|$/.test(f)).map((f, k) => "<tr>" + f.split("|").slice(1, -1).map((c) => (k ? `<td>${inline(c.trim())}</td>` : `<th>${inline(c.trim())}</th>`)).join("") + "</tr>").join("") + "</table>";
    } else if (l.startsWith("> ")) {
      html += `<blockquote>${inline(l.slice(2))}</blockquote>`;
    } else if (l.startsWith("- ")) {
      html += "<ul>";
      while (i < lineas.length && lineas[i].startsWith("- ")) html += `<li>${inline(lineas[i++].slice(2))}</li>`;
      html += "</ul>";
      i--;
    } else if (l.trim() === "---") {
      html += "<hr>";
    } else if (l.trim()) {
      html += `<p>${inline(l)}</p>`;
    }
    i++;
  }
  return html;
}

async function cargarReporte(id) {
  const md = await api(`/api/reporte/${encodeURIComponent(id)}`);
  $("#reporte-md").innerHTML = markdown(md);
  $("#btn-descargar").href = `/api/reporte/${encodeURIComponent(id)}`;
  $("#btn-descargar").setAttribute("download", `reporte-${id}.md`);
  $("#info-reporte").textContent = `Reporte de la ejecución ${id}`;
}

// ===================================================================== inicio
(async function iniciar() {
  // #metricas o #metricas/<id-de-ejecucion>
  const [desdeUrl, ejecucionUrl] = location.hash.slice(1).split("/");
  if ($(`#tab-${desdeUrl}`)) irA(desdeUrl);
  else try { const t = localStorage.getItem("revia-tab"); if (t) irA(t); } catch (_) { /* sin almacenamiento */ }
  await cargarEstado();
  cargarDiff();
  cargarEjecuciones(ejecucionUrl);
  setInterval(sondearTrafico, 1000);
  sondearTrafico();
  // si se recarga la página durante un análisis, se retoma
  const c = await api("/api/corrida?desde=0");
  if (c.existe) {
    resetRun();
    if (!c.terminado) { RUN.envivo = true; $("#btn-ejecutar").disabled = true; $("#btn-ejecutar").textContent = "Analizando…"; }
    sondearCorrida();
  }
})();
