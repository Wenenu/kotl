@echo off
setlocal enabledelayedexpansion
echo ============================================
echo   Building Native EXE with GraalVM
echo ============================================
echo.

:: Set up Visual Studio environment (MSVC)
:: Try to find and call vcvarsall.bat for proper MSVC setup
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
    echo Detecting Visual Studio installation...
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VS_PATH=%%i"
    
    if defined VS_PATH (
        echo Found Visual Studio at: !VS_PATH!
        call "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
        echo MSVC environment configured.
    )
) else (
    echo vswhere not found, trying manual MSVC paths...
)

:: Fallback: Set common MSVC paths manually if vcvars didn't work
:: Adjust these paths to match your Visual Studio installation
if not defined VCINSTALLDIR (
    echo Setting manual MSVC paths...
    
    :: Visual Studio 2022 Community (most common)
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC" (
        for /d %%v in ("C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\*") do set "MSVC_PATH=%%v\bin\Hostx64\x64"
    )
    :: Visual Studio 2022 Professional
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC" (
        for /d %%v in ("C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\*") do set "MSVC_PATH=%%v\bin\Hostx64\x64"
    )
    :: Visual Studio 2022 BuildTools
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC" (
        for /d %%v in ("C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*") do set "MSVC_PATH=%%v\bin\Hostx64\x64"
    )
    :: Visual Studio 2019 Community
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC" (
        for /d %%v in ("C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\*") do set "MSVC_PATH=%%v\bin\Hostx64\x64"
    )
    :: Visual Studio 2019 BuildTools
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC" (
        for /d %%v in ("C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\*") do set "MSVC_PATH=%%v\bin\Hostx64\x64"
    )
    
    if defined MSVC_PATH (
        echo Found MSVC at: %MSVC_PATH%
        set "PATH=%MSVC_PATH%;%PATH%"
    ) else (
        echo WARNING: Could not find MSVC installation!
        echo Please install Visual Studio Build Tools or set MSVC path manually.
    )
)

:: Set GraalVM in PATH (after MSVC so GraalVM tools take priority, but MSVC cl.exe is available)
set "PATH=D:\GraalVM\graalvm-jdk-17.0.17+8.1\bin;%PATH%"

:: Verify cl.exe is found
echo.
echo Checking for cl.exe...
where cl.exe 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo WARNING: cl.exe not found in PATH!
)
echo.

:: Navigate to libs directory
cd /d "%~dp0build\libs"

:: Check if the JAR exists
if not exist "KotlinPCInfo-1.0-SNAPSHOT-all.jar" (
    echo ERROR: KotlinPCInfo-1.0-SNAPSHOT-all.jar not found!
    echo Please build the project first using: gradlew shadowJar
    pause
    exit /b 1
)

echo Found JAR file, starting native-image compilation...
echo This may take several minutes...
echo.

:: Run native-image
native-image --no-fallback --static -jar KotlinPCInfo-1.0-SNAPSHOT-all.jar

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo   BUILD SUCCESSFUL!
    echo   Output: build\libs\KotlinPCInfo-1.0-SNAPSHOT-all.exe
    echo ============================================
) else (
    echo.
    echo ============================================
    echo   BUILD FAILED!
    echo   Check the error messages above.
    echo ============================================
)

pause
