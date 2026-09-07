@echo off
cd /d "%~dp0"
python rdesk_v2.py %*
if errorlevel 1 pause
