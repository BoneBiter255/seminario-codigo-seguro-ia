@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   PASO 1: MOSTRAR EL FALLO DE SEGURIDAD (el "robo")
echo ============================================================
echo.
echo Levantando la app vulnerable en una ventana aparte...
start "banco-de-pruebas (dejala abierta)" .venv\Scripts\python.exe target\mock\run_target.py --port 8081
timeout /t 3 >nul

echo.
echo --- A) Ana pide SOLO sus propios pedidos (esto esta bien) ---
echo.
curl -s -H "Authorization: Bearer token-ana" http://127.0.0.1:8081/api/orders
echo.
echo.
echo --- B) Ana pide el pedido SECRETO de Bruno (esto NO deberia poder) ---
echo.
curl -s -H "Authorization: Bearer token-ana" http://127.0.0.1:8081/api/orders/ord-9
echo.
echo.
echo ============================================================
echo   Ves el nombre, documento y telefono de BRUNO ahi arriba?
echo   Ana no deberia poder verlos. ESE es el fallo de seguridad
echo   que mi proyecto detecta y prueba.
echo ============================================================
echo.
echo   Ahora cierra esto y haz doble clic en  DEMO-CON-IA.bat
echo   (o en DEMO-SIN-IA.bat si no tienes clave de Claude).
echo.
pause
