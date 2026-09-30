@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   DEMO COMPLETA: banco de pruebas + las 3 capas del pipeline
echo ============================================================
echo.
echo   Despliega el banco vulnerable, muestra el ataque y recorre
echo   SAST, triaje (sin IA vs LLM gratuito), verificacion por PoC,
echo   metricas y reporte. Pulsa Enter para avanzar cada paso.
echo.
echo   LLM gratuito: Ollama local (ollama serve) o GEMINI_API_KEY /
echo   GROQ_API_KEY. Sin ninguno, la demo corre solo con el baseline.
echo.

if exist "clave.txt" set /p ANTHROPIC_API_KEY=<clave.txt

set PYTHONPATH=pipeline/src
.venv\Scripts\python.exe -m revia.demo %*

echo.
pause
