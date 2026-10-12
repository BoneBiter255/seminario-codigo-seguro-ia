# Guion del video técnico (máx. 5 minutos)

Todo el video se graba sobre la interfaz web (`ABRIR-REVIA.bat`). Cada bloque
indica qué pestaña mostrar, qué hacer y qué criterio de la rúbrica cubre.

> **Antes de grabar**
> 1. Abre Ollama (o ejecuta `ollama serve`).
> 2. Doble clic en `ABRIR-REVIA.bat`; arriba a la derecha los tres indicadores
>    deben estar en verde (banco vulnerable, banco corregido, LLM).
> 3. Deja corrida al menos una ejecución de cada tipo para que el historial de
>    la pestaña Métricas tenga con qué comparar (ver "Ejecuciones de respaldo").
> 4. El triaje con el modelo 7B tarda ~3,5 min para 19 hallazgos: graba la
>    espera completa y acelérala en la edición (indícalo en pantalla: "x8").

---

## 0:00 – 0:35 · Problema, hipótesis y dónde está la IA
**Pestaña 1 · Arquitectura**

- Lee el problema y la hipótesis de las dos tarjetas superiores.
- Señala el diagrama: código → determinista → **triaje con LLM (morado)** →
  verificación por PoC contra el banco → validación del fix → reporte.
- Frase clave: *"La IA opina, la PoC decide. Ningún veredicto sin evidencia."*

Cubre: claridad, ubicación del componente de IA.

## 0:35 – 1:20 · Escenario normal vs. ataque vs. control
**Pestaña 2 · Escenarios de prueba** → botón «Ejecutar todas las peticiones»

- Fila «Ana lista sus pedidos»: 200 en ambos bancos (uso normal).
- Fila «Ana abre el pedido ord-9 (de Bruno)»: **200 con los datos de Bruno
  resaltados** en el banco vulnerable, **403** en el corregido.
- Muestra el panel «El fix aplicado»: dos cambios mínimos (comparar el
  propietario y exigir el token de servicio).
- Muestra el «Tráfico recibido por los bancos»: son peticiones reales.

Cubre: escenarios de prueba, escenario de control, demostración funcional.

## 1:20 – 3:00 · El pipeline en vivo y la evidencia de la IA
**Pestaña 3 · Análisis en vivo** → Escenario *Vulnerable*, Triaje *Con IA*,
proveedor *ollama*, modelo *qwen2.5-coder:7b* → «Ejecutar análisis»

1. La capa determinista encuentra **19 hallazgos** en milisegundos.
2. Mientras la IA analiza, el panel derecho muestra **la entrada exacta al
   modelo**: el hallazgo, el mapa de archivos y el código marcado como
   `<codigo_no_confiable>` (defensa ante prompt injection).
3. Cuando responde, muestra **la salida**: JSON validado con veredicto,
   confianza, razonamiento, estrategia de PoC y corrección.
4. Haz clic en dos hallazgos para contrastar:
   - `ToolsHealthIndicator.java` (inyección de comandos con argumentos
     constantes): la regla grita, la IA lo descarta como ruido.
   - `PasswordResetService.java:34` (la línea de log imprime el token de
     restablecimiento): una regla "ruidosa" que aquí sí acierta; el baseline
     sin IA lo descarta, la IA lo mantiene porque lee qué se registra.
   - Para ser honestos, el 7B falla en dos: descarta el `new Random()` que
     genera ese mismo token y el SSRF de `WebhookController.java`. qwen3:8b
     con razonamiento acierta ambos.
5. Capa 3: el IDOR de `OrderController.java` → **PoC confirmada**; abre la
   evidencia (petición y respuesta con la PII de Bruno).
6. Capa 4: **validación del fix** → la misma PoC falla contra el banco
   corregido y Ana sigue viendo su propio pedido (regresión OK).

Cubre: evidencia del componente de IA (entrada, flujo, salida), demostración
de extremo a extremo.

## 3:00 – 4:15 · Resultados y métricas
**Pestaña 4 · Métricas** (se abre la ejecución recién terminada)

- Tarjetas de criterios: valor medido, umbral y si cumple.
- Gráfico de barras: SAST solo vs. sin IA vs. con IA (precisión, recall, F1).
- Falsos positivos que llegan a revisión humana: 9 → 2.
- Tabla «Decisión por hallazgo»: ✓/✗ de cada configuración contra la
  etiqueta humana.
- Historial: compara modelos (qwen3:8b con razonamiento llega a F1 0.90 pero
  tarda ~31 s por hallazgo) y el **escenario de control** con 0 falsas
  confirmaciones.
- Abre la ejecución del escenario *corregido* con IA y señala en «Decisión
  por hallazgo» el IDOR de `InternalUserController.java`: la IA dijo «Real»,
  pero la PoC lo **refutó** contra el código corregido. La evidencia manda
  sobre la opinión del modelo.

Cubre: resultados y métricas cuantitativas.

## 4:15 – 5:00 · Limitaciones y reporte
**Pestaña 5 · Reporte** (y volver a Métricas si hace falta)

Di las limitaciones explícitamente:
- El dataset es pequeño (19 hallazgos) y lo construyó el equipo: las cifras
  ilustran el método, no lo validan estadísticamente.
- Recall 0.80 < 0.90 con el 7B: descarta dos hallazgos reales (Random para
  un token y un SSRF). El criterio de cobertura no se cumple con ese modelo.
- Si la IA descarta como ruido un hallazgo explotable, la PoC no se lanza
  (se vio con qwen3 sin razonamiento: 2/3 confirmados).
- Las PoC son plantillas por endpoint, no generadas por el modelo; el banco
  en ejecución es una réplica en Python de los servicios Spring.
- Modelos más grandes aciertan más pero son más lentos (compromiso
  precisión/tiempo).

Cierra con el reporte auditable: cada hallazgo guarda lo que dijo la regla,
lo que opinó la IA y lo que demostró la PoC.

---

## Ejecuciones de respaldo

Si algo falla durante la grabación, la pestaña Métricas conserva las
ejecuciones anteriores (carpeta `out/web/`). Recomendado tener:

| Escenario | Triaje | Para qué |
|---|---|---|
| Vulnerable | Con IA · qwen2.5-coder:7b | demo principal |
| Vulnerable | Con IA · qwen3:8b | comparación de modelos |
| Vulnerable | Sin IA | grupo de control del triaje |
| Corregido | Con IA · qwen2.5-coder:7b | escenario de control: PoC refuta, 0 falsas confirmaciones |
