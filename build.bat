@echo off
setlocal enabledelayedexpansion
echo ============================================
echo   Building Kotlin Project
echo ============================================
echo.

:: Check if gradlew exists
if not exist "gradlew.bat" (
    echo ERROR: gradlew.bat not found!
    echo Please ensure Gradle wrapper is set up.
    pause
    exit /b 1
)

echo.
echo Building project with Gradle...
echo.

:: Build the project (shadowJar creates the fat JAR)
call gradlew.bat shadowJar

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo   BUILD SUCCESSFUL!
    echo   Output: build\libs\KotlinPCInfo-1.0-SNAPSHOT-all.jar
    echo ============================================
    echo.
    echo To run the application:
    echo   java -jar build\libs\KotlinPCInfo-1.0-SNAPSHOT-all.jar
    echo.
    echo To build native executable:
    echo   build-exe.bat
    echo.
) else (
    echo.
    echo ============================================
    echo   BUILD FAILED!
    echo   Check the error messages above.
    echo ============================================
    pause
    exit /b 1
)

pause

