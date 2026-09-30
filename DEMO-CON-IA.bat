@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   DEMO: pipeline de revision de codigo seguro CON LLM
echo ============================================================
echo.

if exist "clave.txt" (
  set /p ANTHROPIC_API_KEY=<clave.txt
  echo [*] Usando API key cargada desde clave.txt
) else (
  echo [*] No se detecto clave.txt. Se usara un LLM gratuito: Ollama local
  echo     ^(si esta corriendo^) o Gemini/Groq si hay GEMINI_API_KEY / GROQ_API_KEY.
  echo     Si no hay ninguno disponible, el pipeline lo avisa y usa el baseline.
)

echo [1/2] Levantando el banco de pruebas vulnerable en una ventana aparte...
start "banco-de-pruebas (dejala abierta)" .venv\Scripts\python.exe target\mock\run_target.py --port 8081
timeout /t 3 >nul

echo [2/2] Ejecutando el pipeline con triaje LLM y evaluacion de metricas:
echo.
set PYTHONPATH=pipeline/src
.venv\Scripts\python.exe -m revia.pipeline --con-verificacion --evaluar

echo.
echo ============================================================
echo   Listo. El reporte quedo en  out\reporte.md
echo   Puedes cerrar la ventana "banco-de-pruebas".
echo ============================================================
pause
