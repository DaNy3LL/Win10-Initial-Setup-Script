@echo off
cls
echo Executing Custom Preset from custom.preset
powershell.exe -NoProfile -ExecutionPolicy Bypass -File %~dp0..\Main Scripts\Tweaks.ps1 -preset "%~dp0custom.preset"
