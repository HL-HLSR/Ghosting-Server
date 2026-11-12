@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem Ghosting Server: change the settings below, see README.md
set SERVER_NAME=Ghosting server
set PORT=22228
set MAX_PLAYERS=16
node index.js
pause
