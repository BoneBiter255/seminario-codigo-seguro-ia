@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   DEMO: pipeline de revision de codigo seguro CON Claude
echo ============================================================
echo.

REM --- Lee la API key desde el archivo clave.txt (que tu creas) ---
if not exist "clave.txt" (
  echo [!] No encontre el archivo "clave.txt".
  echo.
  echo     Crea un archivo llamado  clave.txt  en esta misma carpeta
  echo     y pega dentro tu API key de Claude ^(empieza por sk-ant-...^).
  echo     Guardalo y vuelve a hacer doble clic en este archivo.
  echo.
  pause
  exit /b 1
)
set /p ANTHROPIC_API_KEY=<clave.txt

echo [1/2] Levantando el banco de pruebas vulnerable en una ventana aparte...
start "banco-de-pruebas (dejala abierta)" .venv\Scripts\python.exe target\mock\run_target.py --port 8081
timeout /t 3 >nul

echo [2/2] Ejecutando el pipeline. Veras el triaje de Claude hallazgo por hallazgo:
echo.
.venv\Scripts\python.exe -m revia.pipeline --con-verificacion --evaluar

echo.
echo ============================================================
echo   Listo. El reporte quedo en  out\reporte.md
echo   Puedes cerrar la ventana "banco-de-pruebas".
echo ============================================================
pause
