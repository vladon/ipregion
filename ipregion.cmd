@echo off
rem ipregion launcher for cmd.exe: delegates to the PowerShell wrapper
rem (bypasses the execution policy, so no Set-ExecutionPolicy is needed).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ipregion.ps1" %*
exit /b %ERRORLEVEL%
