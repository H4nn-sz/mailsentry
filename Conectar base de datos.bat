@echo off
chcp 65001 >nul
title MailSentry - Conectar base de datos (Supabase)
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Ejecute primero "Iniciar MailSentry.bat" para preparar el programa.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" main.py conectar-bd
echo.
pause
