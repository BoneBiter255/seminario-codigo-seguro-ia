# 🎬 Cómo mostrar mi proyecto (guía súper simple)

> Esta guía es para ti. Sigue los pasos en orden. No necesitas saber programar.
> Solo vas a **hacer doble clic en 3 archivos** y **leer lo que aparece**.

---

## 🧸 Explícalo así (para que cualquiera lo entienda)

Imagina una **casa con muchas puertas**. La casa es una aplicación de internet.

- Algunas puertas **no tienen cerradura** → eso es un fallo de seguridad.
- Las herramientas viejas solo **gritan** "¡creo que una puerta está abierta!"… muchas veces, incluso cuando NO lo está. Eso cansa y la gente deja de hacerles caso.
- **Mi proyecto** revisa cada puerta y, si de verdad está abierta, **entra y saca una galleta para demostrarlo**. Ya no dice "creo que"; dice **"mira, aquí está la prueba"**.

Esa **prueba** es lo nuevo y lo importante de mi trabajo.

---

## ✅ Antes de empezar (solo una vez)

1. Abre la carpeta del proyecto en el **Escritorio**:
   `seminario-codigo-seguro-ia`
2. Para la parte con **Inteligencia Artificial gratis**, usa **Ollama** (corre en tu PC, sin clave):
   - Instálalo desde **https://ollama.com** y, en una terminal, ejecuta una sola vez:
     `ollama pull qwen2.5-coder:7b` (descarga ~4.7 GB).
   - Antes de la demo, asegúrate de que Ollama esté abierto (o ejecuta `ollama serve`).
   - Alternativa sin instalar nada: una clave gratuita de Gemini en **https://aistudio.google.com**
     guardada en la variable de entorno `GEMINI_API_KEY`.
   - Si no hay ningún LLM disponible, la demo lo avisa y sigue con la versión **SIN IA**.

> 🔒 `clave.txt` es solo tuyo y nunca se sube a internet. No lo compartas.

---

## 🎥 La demostración: 3 dobles clic

> ⭐ **Atajo: `DEMO-COMPLETA.bat`** hace todo en un solo doble clic: levanta el banco
> de pruebas, muestra el ataque y recorre cada capa (SAST → triaje sin IA vs con LLM →
> PoC → métricas → reporte). Pulsa **Enter** para avanzar cada paso.

### 👉 Doble clic 1 — Mostrar el fallo: `VER-EL-ATAQUE.bat`

Aparecerán dos respuestas:
- **A)** "Ana" pide **sus** pedidos → correcto.
- **B)** "Ana" pide el pedido **secreto de Bruno** → y ¡le salen el **nombre, documento y teléfono de Bruno**!

**Qué decir:**
> "Ana no debería poder ver los datos de Bruno, pero puede. Este es un fallo real llamado IDOR, y además cruza dos servicios, por eso las herramientas normales no lo ven."

---

### 👉 Doble clic 2 — Mostrar mi solución: `DEMO-CON-IA.bat`

(Si no tienes Ollama ni clave, usa **`DEMO-SIN-IA.bat`**.)

Verás cómo el sistema revisa cada hallazgo **uno por uno, en tiempo real**, así:
```
[triaje LLM ollama:qwen2.5-coder:7b] 3/9  ...secreto-embebido ...
    -> veredicto: verdadero_positivo  (confianza 0.90, P1)
```

**Qué decir:**
> "El sistema encontró 9 avisos. La Inteligencia Artificial lee el código de verdad y descarta los que son ruido. Y lo más importante: **lanza una prueba de concepto** que confirma cuáles se pueden explotar de verdad."

---

### 👉 Doble clic 3 (opcional) — Mostrar el resultado escrito

Abre el archivo **`out\reporte.md`** (doble clic o arrástralo a tu navegador / VS Code).

**Qué decir:**
> "Este es el reporte final. Cada fallo confirmado trae su **prueba adjunta**, para que un humano pueda revisarlo sin tener que creerle a la máquina."

---

## 🔢 Los 3 números para señalar (apréndetelos)

Cuando corras la demo, al final salen unas métricas. Señala esto:

| Antes (herramienta sola) | Después (mi proyecto) |
|---|---|
| 3 falsas alarmas | **0 falsas alarmas** |
| Precisión 67% | **Precisión 100%** |
| Sin pruebas | **Explotabilidad probada 3 de 3** |

**Qué decir:**
> "Eliminé todas las falsas alarmas y, además, probé de verdad los fallos reales."

---

## 🆘 Si algo sale mal

- **No aparece nada / error de conexión:** cierra todo y vuelve a empezar por el Doble clic 1 (a veces la ventana de la app tarda unos segundos en encender).
- **La IA no responde o da error:** usa **`DEMO-SIN-IA.bat`**. Funciona sin internet y muestra los mismos números. Es tu red de seguridad.
- **Deja siempre abierta** la ventanita que dice *"banco-de-pruebas"*; es la app encendida. Ciérrala solo al terminar.

---

## 🗣️ Tu frase de cierre (para el profesor)

> "El estado del arte dice que la IA revisando código **alucina** y su veredicto **no trae pruebas**. Mi proyecto añade una **capa de verificación independiente**: no confía en la opinión de la IA, la **comprueba con una prueba reproducible**. Por eso el resultado es **auditable**."
