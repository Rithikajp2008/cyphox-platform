@echo off
cd /d %~dp0
if not exist .venv\Scripts\python.exe (
  echo Create the venv first: py -m venv .venv
  exit /b 1
)
.venv\Scripts\python.exe -m uvicorn tamper_app.main:app --host 127.0.0.1 --port 8004 --reload
