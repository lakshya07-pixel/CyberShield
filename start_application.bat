@echo off
REM ============================================================================
REM Bharat AI-SoC Challenge — Dual-Mode Full-Stack Startup Script
REM ============================================================================

echo Starting Bharat AI-SoC Unified Backend on http://127.0.0.1:8000 ...
start "Bharat AI-SoC Backend" /min cmd /c "python -m uvicorn backend_api.main:app --host 127.0.0.1 --port 8000"

timeout /t 2 /nobreak >nul

echo Starting Bharat AI-SoC Frontend UI on http://localhost:5173 ...
start "Bharat AI-SoC Frontend" /min cmd /c "npm --prefix frontend run dev"

echo.
echo Application initialized!
echo Backend:  http://127.0.0.1:8000/api/v1/health
echo Frontend: http://localhost:5173 (Supports both Expert Mode & User Mode)
echo.
pause

