@echo off
cls
echo Executing DaNy3LL's preset from dany3ll.preset
echo ----------------------------------------------
PowerShell -NoProfile -ExecutionPolicy Bypass -File "..\Main Scripts\Tweaks.ps1" -preset "dany3ll.preset"
