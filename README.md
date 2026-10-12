# REVIA — Revisión de código seguro asistida por IA con verificación independiente

> Prototipo del Seminario de Investigación. Implementa la propuesta de las
> diapositivas: un pipeline híbrido que combina un motor determinístico, triaje
> con un modelo de lenguaje y una **capa de verificación** que adjunta una prueba
> de concepto reproducible a cada hallazgo confirmado.

## El problema en una frase

Los veredictos de seguridad producidos por IA no son verificables ni auditables:
el SAST tradicional genera demasiados falsos positivos y la IA generativa alucina
en las dos direcciones (inventa vulnerabilidades y aprueba código inseguro).

## La idea

Ninguna capa por sí sola es de fiar, así que el pipeline las encadena y hace que
**la evidencia mande sobre la opinión**:

```
  Código  ─►  Capa determinista  ─►  Triaje con LLM  ─►  Verificación (PoC)  ─►  Reporte auditable
              (SAST · reglas)         (dedup · filtra      (genera y ejecuta      (+ revisión humana)
                                        FP · prioriza)       una prueba real)
```

- **Capa determinista** — motor de reglas propio (funciona solo con Python) más
  un adaptador opcional a Semgrep. Sobre-reporta a propósito; es la fuente de
  cobertura. Detecta el IDOR por *ausencia* de la comprobación de propiedad, no
  por una línea peligrosa.
- **Triaje con LLM** (Ollama local, Gemini, Groq o Claude) — lee el código real de cada hallazgo y emite una
  **hipótesis** estructurada (verdadero/falso positivo/incierto, impacto,
  estrategia de PoC, corrección). Trata el código revisado como dato hostil para
  resistir *prompt injection* embebido.
- **Verificación independiente** — el núcleo. Lanza una PoC real contra el
  servicio en ejecución. Si la PoC confirma, el hallazgo asciende a
  *CONFIRMADO_EXPLOTABLE* aunque el triaje dudara; si la refuta, cae a
  *REFUTADO_POR_POC* aunque el triaje estuviera seguro.

## El banco de pruebas

Tres microservicios Spring Boot con un **IDOR cross-service** inyectado:
`order-service` autentica al llamante pero nunca compara el propietario del
pedido, y propaga la PII del tercero desde `user-service`. Ninguna herramienta
que mire un solo servicio ve la cadena completa. `notification-service` aporta
casos donde la decisión depende del contexto: reglas "ruidosas" que esta vez
aciertan y reglas "precisas" que esta vez se equivocan.

Hay dos escenarios con el mismo código salvo el fix:

| Escenario | Código | Verdad de terreno | Para qué |
|---|---|---|---|
| Vulnerable | `target/` | `dataset/ground-truth.yml` (19 hallazgos) | demostración principal |
| Corregido (control) | `target-corregido/` | `dataset/ground-truth-corregido.yml` | escenario de control y validación del fix |

El código Java no lleva comentarios que revelen la respuesta (nada de
"VULNERABILIDAD (CWE-…)"): el LLM ve lo mismo que vería un revisor real. Las
justificaciones de cada etiqueta viven en el dataset.

El mismo contrato HTTP está replicado en `target/mock/run_target.py` (solo
Python, modos `vulnerable` y `corregido`) para que la verificación corra en
cualquier máquina y en CI sin Maven ni Docker.

## Interfaz web (recomendado)

Doble clic en **`ABRIR-REVIA.bat`** (o `python -m revia.web.servidor` con
`PYTHONPATH=pipeline/src`). Levanta los dos bancos de pruebas y abre
<http://127.0.0.1:8765> con cinco pestañas:

1. **Arquitectura**: problema, hipótesis y diagrama con el componente de IA
   resaltado; se anima mientras corre un análisis.
2. **Escenarios de prueba**: las mismas peticiones contra el banco vulnerable y
   el corregido (uso normal, acceso indebido, sin sesión), el tráfico que
   reciben los bancos y el diff del fix.
3. **Análisis en vivo**: corre el pipeline y muestra, por hallazgo, la entrada
   exacta al modelo, su salida JSON, el tiempo, la PoC y el estado final.
4. **Métricas**: criterios de éxito (`dataset/criterios.yml`) con umbral y
   resultado, precisión/recall/F1 de SAST solo vs. sin IA vs. con IA, falsos
   positivos, matriz de confusión, tiempos, decisión por hallazgo, validación
   de fixes e historial de ejecuciones.
5. **Reporte**: el reporte auditable de la ejecución, descargable.

Las ejecuciones se guardan en `out/web/`. El guion del video está en
[`docs/guion-video.md`](docs/guion-video.md).

## Cómo ejecutarlo por línea de comandos

Ya hay un entorno virtual en `.venv` con todo instalado. Desde la raíz del
proyecto:

```bash
# 1) Levantar el banco de pruebas vulnerable (en una terminal)
.venv/Scripts/python.exe target/mock/run_target.py --port 8081

# 2) Correr el pipeline completo con verificación y métricas (en otra terminal)
.venv/Scripts/python.exe -m revia.pipeline --con-verificacion --evaluar

# Variante de control, sin IA (baseline heurístico, sin credenciales):
.venv/Scripts/python.exe -m revia.pipeline --sin-ia --con-verificacion --evaluar
```

El reporte auditable queda en `out/reporte.md` y `out/reporte.json`.

### Demo completa (un doble clic)

`DEMO-COMPLETA.bat` (o `python -m revia.demo`) despliega el banco de pruebas y
recorre cada componente paso a paso: el ataque en vivo, la capa determinista, el
triaje **sin IA vs con LLM gratuito**, las PoC de verificación, las métricas
comparadas y el reporte. Usa `--sin-pausas` para correrla de corrido.

### Activar el triaje con un LLM gratuito

Todos los proveedores reciben el mismo prompt y el mismo esquema de salida
(`TriageVerdict`). Con `--proveedor auto` (por defecto) se usa el primero
disponible: Gemini → Groq → Claude (si hay key) → Ollama local.

```bash
# Ollama: local, gratis y sin API key (recomendado para la demo)
ollama pull qwen2.5-coder:7b
.venv/Scripts/python.exe -m revia.pipeline --proveedor ollama --con-verificacion --evaluar

# Google Gemini (tier gratuito): pip install google-genai
export GEMINI_API_KEY="..."
.venv/Scripts/python.exe -m revia.pipeline --proveedor gemini --con-verificacion --evaluar

# Groq (tier gratuito): pip install groq
export GROQ_API_KEY="..."
.venv/Scripts/python.exe -m revia.pipeline --proveedor groq --con-verificacion --evaluar

# Claude (de pago)
export ANTHROPIC_API_KEY="sk-ant-..."
.venv/Scripts/python.exe -m revia.pipeline --proveedor claude --con-verificacion --evaluar
```

Si no hay ningún proveedor, o si una llamada falla, el pipeline **no falla ni
inventa**: ese hallazgo cae al baseline heurístico, queda marcado como
`[degradado a heuristica]` en el razonamiento y el reporte indica cuántos se
degradaron. Así una cifra de "triaje con IA" nunca esconde respuestas que no dio
el modelo. El baseline es además el grupo de control contra el que se mide si el
LLM aporta valor.

## Resultados del prototipo

Escenario vulnerable, 19 hallazgos etiquetados (10 reales, 9 ruido), modelos
locales en una RTX 4060 de 8 GB, medidos el 2026-10-12 con la interfaz web:

| Configuración | Precisión | Recall | F1 | FP | Tiempo por hallazgo |
|---|---|---|---|---|---|
| SAST solo | 0.53 | 1.00 | 0.69 | 9 | — |
| Pipeline + baseline sin IA | 0.60 | 0.60 | 0.60 | 4 | — |
| Pipeline + `qwen2.5-coder:7b` | 0.80 | 0.80 | 0.80 | 2 | 10.5 s |
| Pipeline + `qwen3:8b` (razonamiento activado) | 0.90 | 0.90 | **0.90** | 1 | 31.5 s |
| Pipeline + `qwen3:8b` (razonamiento desactivado) | 0.83 | 0.50 | 0.63 | 1 | 11.9 s |

- Explotables confirmados por PoC: **3/3** con ambos modelos con buen
  desempeño, **0 falsas confirmaciones**.
- Fixes validados: **100 %** (la PoC falla contra el código corregido y el uso
  legítimo sigue funcionando).
- Escenario de control (corregido): **0** confirmaciones.

Lectura:

> El baseline sin IA es peor que el SAST solo: decidir por la "fama" de la
> regla falla justo donde el contexto importa (un `Random` que genera un token,
> un IDOR sobre un catálogo público). Leer el código es lo que aporta la IA.

> El 7B cumple F1 ≥ 0.80 pero no el recall ≥ 0.90: descarta un `Random` usado
> para el token de restablecimiento y un SSRF. qwen3:8b con razonamiento cumple
> ambos a cambio de triplicar el tiempo. Sin razonamiento, qwen3 descarta uno
> de los IDOR reales y su PoC nunca se lanza (2/3).

> El dataset es pequeño y lo construyó el equipo: estas cifras **ilustran el
> método, no lo validan estadísticamente**.

## Pruebas

```bash
.venv/Scripts/python.exe -m pytest pipeline/tests -q
```

Las pruebas levantan el objetivo mock real en un hilo y verifican la exfiltración
de verdad — no con dobles de prueba.

## Estructura

```
seminario-codigo-seguro-ia/
├─ pipeline/                 # el orquestador (Python)
│  ├─ src/revia/
│  │  ├─ models.py           # contrato de datos entre capas
│  │  ├─ layers/
│  │  │  ├─ deterministic.py # capa 1: motor de reglas + Semgrep
│  │  │  ├─ triage.py        # capa 2: triaje con LLM (Ollama/Gemini/Groq/Claude)
│  │  │  └─ verification.py  # capa 3: PoC contra el objetivo vivo
│  │  ├─ escenarios.py       # vulnerable / corregido
│  │  ├─ motor.py            # pipeline con eventos, métricas y validación del fix
│  │  ├─ web/                # interfaz web (servidor.py + static/)
│  │  ├─ evaluation/metrics.py
│  │  ├─ report/render.py
│  │  ├─ pipeline.py         # CLI que une las tres capas
│  │  └─ demo.py             # demo guiada paso a paso (DEMO-COMPLETA.bat)
│  ├─ rules/java-spring.yml  # reglas deterministas
│  └─ tests/
├─ target/                   # banco de pruebas vulnerable
│  ├─ order-service/         # microservicio Spring Boot (IDOR)
│  ├─ user-service/          # microservicio Spring Boot (PII)
│  ├─ notification-service/  # casos que dependen del contexto
│  └─ mock/run_target.py     # réplica ejecutable solo-Python
├─ target-corregido/         # mismo código con el fix (escenario de control)
├─ dataset/
│  ├─ ground-truth.yml       # verdad de terreno etiquetada
│  ├─ ground-truth-corregido.yml
│  └─ criterios.yml          # criterios de éxito y umbrales
├─ docs/arquitectura.md
└─ .github/workflows/pipeline.yml  # integración en CI
```

## Estado y próximos pasos

Este es el entregable de las primeras fases del cronograma (estado del arte,
arquitectura, capas determinística y de triaje, y una capa de verificación
funcional). Lo pendiente, en orden:

1. Sustituir las plantillas de PoC por síntesis guiada por el triaje, ejecutada
   en un sandbox aislado.
2. Ejecutar los microservicios Spring reales (no solo el mock) en CI vía Docker.
3. Ampliar el dataset con más CWE y con casos reales para dar valor estadístico
   a las métricas.
4. Añadir *reachability* real en la capa de SCA.

### Limitaciones conocidas

- Si el triaje descarta como ruido un hallazgo explotable, la PoC no se lanza
  y el hallazgo se pierde (visto con qwen3:8b sin razonamiento).
- Cada plantilla de PoC solo respalda hallazgos del endpoint que prueba; el
  resto de CWE queda como "probable, sin verificar".
- La validación del fix usa el parche de referencia de `target-corregido/`, no
  un parche generado por el modelo.
- `target-adversarial/` (comentarios de inyección de prompt) existe pero no
  está integrado a la interfaz ni a las métricas.
