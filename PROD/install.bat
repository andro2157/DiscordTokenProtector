@echo off
title Discord Token Protector Installer
echo ==========================================================
echo Discord Token Protector Installer
echo Dev build.
echo By Andro24
echo ==========================================================
echo.

set "workingPath=%APPDATA%\DiscordTokenProtector\"

if exist "%workingPath%\DiscordTokenProtector.exe" goto oldInstall
if exist "%workingPath%\glfw3.dll" goto oldInstall
if exist "%workingPath%\ProtectionPayload.dll" goto oldInstall

call :checkExists DiscordTokenProtector.exe 
call :checkExists glfw3.dll
call :checkExists ProtectionPayload.dll

call :install
echo Installation complete!
:end
pause
exit

:oldInstall
echo An old installation has been detected.
echo Would you like to (R)emove it or (U)pdate it?
choice /C RU
if %errorlevel%==1 call :removeOld
if %errorlevel%==2 call :update
goto end

:install
if not exist "%workingPath%" md "%workingPath%"
echo Copying new files...
copy DiscordTokenProtector.exe "%workingPath%\DiscordTokenProtector.exe"
copy glfw3.dll "%workingPath%\glfw3.dll"
copy ProtectionPayload.dll "%workingPath%\ProtectionPayload.dll"
echo Done.
echo.
exit /b

:update
call :removeOld
call :install
exit /b

:removeOld
echo Removing old versions...
call :removeOld "%workingPath%\DiscordTokenProtector.exe"
call :removeOld "%workingPath%\glfw3.dll"
call :removeOld "%workingPath%\ProtectionPayload.dll"
echo Done.
echo.
exit /b

REM arg : filepath
:removeOld
if exist %1 (
	del %1>nul
	echo Detected an old installation of %1. Removed.
)
exit /b
REM arg : filepath
:checkExists
if not exist %1 (
	echo %1 is missing. Please redownload it.
	exit
)
exit /b