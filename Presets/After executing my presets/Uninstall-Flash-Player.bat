@ECHO OFF

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "..\Win10CustomTweaks.ps1" RequireAdmin UninstallFlashPlayer WaitForKey
