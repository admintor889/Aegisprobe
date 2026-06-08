@echo off
REM ============================================================
REM AegisProbe Web UI Launcher (Windows)
REM Prerequisites: Node.js >= 22.14.0, pnpm >= 10.0.0
REM ============================================================

cd /d "%~dp0"

REM Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH.
    echo Please install Node.js >= 22.14.0 from https://nodejs.org
    pause
    exit /b 1
)

REM Check pnpm
pnpm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] pnpm not found, installing...
    npm install -g pnpm
)

REM Install dependencies if needed
if not exist "node_modules" (
    echo [INFO] Installing dependencies...
    pnpm install
)

REM Build if dist missing
if not exist "apps\cli\dist\index.js" (
    echo [INFO] Building packages...
    pnpm build
)

REM Set API key if not configured
if not exist ".env" (
    echo [WARN] .env file not found. Copy .env.example to .env and set DEEPSEEK_API_KEY
    copy .env.example .env
    echo Please edit .env with your DeepSeek API key, then re-run.
    pause
    exit /b 1
)

echo [INFO] Starting AegisProbe Web UI on http://127.0.0.1:3000
node apps/cli/dist/index.js webui --port 3000
pause
