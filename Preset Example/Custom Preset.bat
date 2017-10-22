@echo off
cls
echo Executing Custom Preset from custom.preset
echo ------------------------------------------
PowerShell -NoProfile -ExecutionPolicy Bypass -File "..\Main Scripts\Tweaks.ps1" -preset "custom.preset"
