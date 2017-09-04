@echo off
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0.\Install Chocolatey And Packages.ps1""' -Verb RunAs}"
