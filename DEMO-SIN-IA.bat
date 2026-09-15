@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   DEMO: pipeline de revision de codigo seguro (SIN IA)
echo   Modo baseline: no necesita API key ni internet.
echo ============================================================
echo.

echo [1/2] Levantando el banco de pruebas vulnerable en una ventana aparte...
start "banco-de-pruebas (dejala abierta)" .venv\Scripts\python.exe target\mock\run_target.py --port 8081
timeout /t 3 >nul

echo [2/2] Ejecutando el pipeline en modo baseline:
echo.
.venv\Scripts\python.exe -m revia.pipeline --sin-ia --con-verificacion --evaluar

echo.
echo ============================================================
echo   Listo. El reporte quedo en  out\reporte.md
echo   Puedes cerrar la ventana "banco-de-pruebas".
echo ============================================================
pause
