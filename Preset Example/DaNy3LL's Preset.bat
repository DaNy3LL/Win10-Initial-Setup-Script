@echo off
cls
echo Executing DaNy3LL's preset from dany3ll.preset
echo ----------------------------------------------
PowerShell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Main Scripts\Tweaks.ps1" -preset "%~dp0dany3ll.preset"
