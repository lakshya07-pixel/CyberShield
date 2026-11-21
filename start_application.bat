@echo off
REM ============================================================================
REM CyberShield
REM ============================================================================

echo Starting CyberShield Unified Backend on http://127.0.0.1:8000 ...
start "CyberShield Backend" /min cmd /c "python -m uvicorn backend_api.main:app --host 127.0.0.1 --port 8000"

timeout /t 2 /nobreak >nul

echo Starting CyberShield Frontend UI on http://localhost:5173 ...
start "CyberShield Frontend" /min cmd /c "npm --prefix frontend run dev"

echo.
echo Application initialized!
echo Backend:  http://127.0.0.1:8000/api/v1/health
echo Frontend: http://localhost:5173 (Supports both Expert Mode & User Mode)
echo.
pause
