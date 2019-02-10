@ECHO OFF

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Win10.ps1" -preset "%~dpn0.preset"
