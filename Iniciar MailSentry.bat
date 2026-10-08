@echo off
chcp 65001 >nul
title MailSentry - Detector de phishing
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Preparando MailSentry por primera vez. Esto toma uno o dos minutos...
  py -3 -m venv .venv 2>nul || python -m venv .venv
  ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
)
".venv\Scripts\python.exe" main.py iniciar %*
pause
