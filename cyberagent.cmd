@echo off
cd /d "%~dp0"
node apps\cli\dist\index.js chat --yes
