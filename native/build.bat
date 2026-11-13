@echo off
rem Builds MatrixSys.exe and MatrixSys-Setup.exe with the Visual Studio C++ compiler. No third-party dependencies.
setlocal
cd /d "%~dp0"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR ( echo Visual Studio with C++ tools not found. & exit /b 1 )
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
if not exist out mkdir out
if not exist matrixsys.ico python make_icon.py || exit /b 1
rem a running copy locks its exe: move it aside so the build can proceed, and clear leftovers that are no longer in use
del /q out\MatrixSys.old*.exe >nul 2>&1
if exist out\MatrixSys.exe ren out\MatrixSys.exe MatrixSys.old%RANDOM%.exe
echo 1 ICON "matrixsys.ico"> app.rc
rc /nologo /fo app.res app.rc || exit /b 1
cl /nologo /std:c++17 /O2 /EHsc /MT /W3 /utf-8 /DUNICODE /D_UNICODE main.cpp app.res /Fo:out\ /Fe:out\MatrixSys.exe /link /SUBSYSTEM:WINDOWS || exit /b 1
(echo 1 ICON "matrixsys.ico"& echo 2 RCDATA "out\\MatrixSys.exe")> setup.rc
rc /nologo /fo setup.res setup.rc || exit /b 1
cl /nologo /std:c++17 /O2 /EHsc /MT /W3 /utf-8 /DUNICODE /D_UNICODE setup.cpp setup.res /Fo:out\ /Fe:out\MatrixSys-Setup.exe /link /SUBSYSTEM:WINDOWS /MANIFEST:EMBED "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" || exit /b 1
echo build ok
