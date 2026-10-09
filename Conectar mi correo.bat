@echo off
chcp 65001 >nul
title MailSentry - Conectar mi correo
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Primero abra "Iniciar MailSentry.bat" una vez para instalar MailSentry.
  pause
  exit /b
)
".venv\Scripts\python.exe" main.py agregar-buzon
pause
