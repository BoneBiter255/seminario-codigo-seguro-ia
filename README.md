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
- **Triaje con LLM (Claude)** — lee el código real de cada hallazgo y emite una
  **hipótesis** estructurada (verdadero/falso positivo/incierto, impacto,
  estrategia de PoC, corrección). Trata el código revisado como dato hostil para
  resistir *prompt injection* embebido.
- **Verificación independiente** — el núcleo. Lanza una PoC real contra el
  servicio en ejecución. Si la PoC confirma, el hallazgo asciende a
  *CONFIRMADO_EXPLOTABLE* aunque el triaje dudara; si la refuta, cae a
  *REFUTADO_POR_POC* aunque el triaje estuviera seguro.

## El banco de pruebas

Dos microservicios Spring Boot con un **IDOR cross-service** inyectado:
`order-service` autentica al llamante pero nunca compara el propietario del
pedido, y propaga la PII del tercero desde `user-service`. Ninguna herramienta
que mire un solo servicio ve la cadena completa.

El mismo contrato HTTP está replicado en `target/mock/run_target.py` (solo Python)
para que la verificación corra en cualquier máquina y en CI sin Maven ni Docker.

## Cómo ejecutarlo

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

### Activar el triaje con LLM Especializado y Gratuito

El pipeline soporta múltiples proveedores de LLMs gratuitos, locales y remotos:

```bash
# 1) Triaje con motor LLM especializado gratuito (offline, sin necesidad de credenciales):
.venv/Scripts/python.exe -m revia.pipeline --proveedor specialized --con-verificacion --evaluar

# 2) Triaje con Google Gemini (Gratuito con GEMINI_API_KEY):
export GEMINI_API_KEY="AIzaSy..."
.venv/Scripts/python.exe -m revia.pipeline --proveedor gemini --modelo gemini-2.5-flash --con-verificacion --evaluar

# 3) Triaje con Groq Cloud (Gratuito con GROQ_API_KEY):
export GROQ_API_KEY="gsk_..."
.venv/Scripts/python.exe -m revia.pipeline --proveedor groq --modelo qwen-2.5-coder-32b --con-verificacion --evaluar

# 4) Triaje con Ollama (Local offline):
.venv/Scripts/python.exe -m revia.pipeline --proveedor ollama --modelo qwen2.5-coder --con-verificacion --evaluar
```

## Resultados del prototipo

Sobre el banco de pruebas, comparando *SAST solo*, *Pipeline Baseline* y *Pipeline con Triaje LLM*:

| Configuración | Precisión | Recall | F1 | Falsos positivos |
|---|---|---|---|---|
| SAST solo | 0.67 | 1.00 | 0.80 | 3 |
| Pipeline Baseline (heurístico) | 1.00 | 0.83 | 0.91 | **0** |
| **Pipeline con Triaje LLM Especializado** | **1.00** | **1.00** | **1.00** | **0** |

Explotabilidad confirmada por PoC: **3/3 (100 %)**.


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
│  │  │  ├─ triage.py        # capa 2: triaje con Claude (salida estructurada)
│  │  │  └─ verification.py  # capa 3: PoC contra el objetivo vivo
│  │  ├─ evaluation/metrics.py
│  │  ├─ report/render.py
│  │  └─ pipeline.py         # CLI que une las tres capas
│  ├─ rules/java-spring.yml  # reglas deterministas
│  └─ tests/
├─ target/                   # banco de pruebas vulnerable
│  ├─ order-service/         # microservicio Spring Boot (IDOR)
│  ├─ user-service/          # microservicio Spring Boot (PII)
│  └─ mock/run_target.py     # réplica ejecutable solo-Python
├─ dataset/ground-truth.yml  # verdad de terreno etiquetada
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
