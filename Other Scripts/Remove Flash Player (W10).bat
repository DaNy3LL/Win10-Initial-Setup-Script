@echo off

:: Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

:: If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    cd /D "%~dp0"

echo.
echo Removing Adobe Flash from Windows 10.
echo.
pause

takeown /f "%windir%\System32\Macromed" /r /d y
icacls "%windir%\System32\Macromed" /grant administrators:F /t
rd /s /q "%windir%\System32\Macromed"
echo.

takeown /f "%windir%\SysWOW64\Macromed" /r /d y
icacls "%windir%\SysWOW64\Macromed" /grant administrators:F /t
rd /s /q "%windir%\SysWOW64\Macromed"
echo.

takeown /f "%windir%\SysWOW64\FlashPlayerApp.exe" /r /d y
icacls "%windir%\SysWOW64\FlashPlayerApp.exe" /grant administrators:F /t
rd /s /q "%windir%\SysWOW64\FlashPlayerApp.exe"
takeown /f "%windir%\SysWOW64\FlashPlayerCPLApp.cpl" /r /d y
icacls "%windir%\SysWOW64\FlashPlayerCPLApp.cpl" /grant administrators:F /t
rd /s /q "%windir%\SysWOW64\FlashPlayerCPLApp.cpl"
echo.

rd /s /q "%appdata%\Adobe"
rd /s /q "%appdata%\Macromedia"
echo.

pause
