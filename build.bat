@echo off
REM WinFWMon build script
REM Requirements: Go 1.22+

echo === WinFWMon Build ===
echo.

where go >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Go is not installed or not in PATH.
    echo Download from https://golang.org/dl/
    pause
    exit /b 1
)

go version
echo.

REM rsrc embeds the manifest (DPI awareness + Common Controls v6).
REM lxn/walk requires this - without it the window silently fails to open.
echo Installing rsrc tool...
go install github.com/akavel/rsrc@latest
if %ERRORLEVEL% neq 0 (
    echo ERROR: Could not install rsrc.
    echo Make sure you have internet access.
    pause
    exit /b 1
)

REM Find rsrc.exe - go install puts it in GOPATH\bin or USERPROFILE\go\bin
set "RSRC="
if exist "%GOPATH%\bin\rsrc.exe"       set "RSRC=%GOPATH%\bin\rsrc.exe"
if not defined RSRC (
    if exist "%USERPROFILE%\go\bin\rsrc.exe" set "RSRC=%USERPROFILE%\go\bin\rsrc.exe"
)
if not defined RSRC (
    where rsrc >nul 2>&1
    if %ERRORLEVEL% equ 0 set "RSRC=rsrc"
)
if not defined RSRC (
    echo ERROR: rsrc.exe not found after install.
    echo Expected location: %USERPROFILE%\go\bin\rsrc.exe
    pause
    exit /b 1
)

echo Generating manifest resource (rsrc.syso)...
"%RSRC%" -manifest winfwmon.manifest -o rsrc.syso
if %ERRORLEVEL% neq 0 (
    echo ERROR: rsrc failed. Cannot continue without rsrc.syso.
    pause
    exit /b 1
)
echo rsrc.syso OK.
echo.

echo Downloading dependencies...
go mod tidy
if %ERRORLEVEL% neq 0 (
    echo ERROR: go mod tidy failed.
    pause
    exit /b 1
)
echo.

echo Building WinFWMon.exe ...
go build -ldflags="-s -w -H windowsgui" -o WinFWMon.exe .
if %ERRORLEVEL% neq 0 (
    echo BUILD FAILED.
    pause
    exit /b 1
)

echo.
echo =====================================================
echo  Build successful!
echo.
echo  WinFWMon.exe
echo.
echo  For troubleshooting, run with the --debug flag to
echo  write WinFWMon_debug.log next to the exe:
echo      WinFWMon.exe --debug
echo =====================================================
echo.
echo TIP: Right-click WinFWMon.exe and choose
echo Run as administrator for full functionality.
echo.
pause
