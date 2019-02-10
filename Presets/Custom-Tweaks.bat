@ECHO OFF

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Win10CustomTweaks.ps1" -preset "%~dpn0.preset"
