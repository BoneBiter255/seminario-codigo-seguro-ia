@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   REVIA - interfaz web
echo ============================================================
echo.
echo   Levanta los dos bancos de pruebas (vulnerable y corregido)
echo   y abre la interfaz en el navegador: http://127.0.0.1:8765
echo.
echo   Para el triaje con IA deja Ollama abierto (ollama serve).
echo   Cierra esta ventana o pulsa Ctrl+C para detener todo.
echo.

if exist "clave.txt" set /p ANTHROPIC_API_KEY=<clave.txt

set PYTHONPATH=pipeline/src
.venv\Scripts\python.exe -m revia.web.servidor %*

pause
