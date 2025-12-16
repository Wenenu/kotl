@echo off
echo Building Kotlin application with Java compiler and Gradle JAR...

REM Clean previous build
call gradle clean

REM Compile Kotlin code using Java/Kotlin compiler via Gradle
echo Compiling Main.kt and dependencies...
call gradle compileKotlin

REM Check if compilation was successful
if %errorlevel% neq 0 (
    echo Kotlin compilation failed!
    pause
    exit /b 1
)

REM Build the JAR file with MainKt as main class
echo Creating JAR file...
call gradle jar

REM Check if JAR creation was successful
if %errorlevel% neq 0 (
    echo JAR creation failed!
    pause
    exit /b 1
)

echo Build successful!
echo JAR file should be located in build/libs/

REM Optional: List the generated JAR files
echo Generated JAR files:
dir build\libs\*.jar /b 2>nul
if %errorlevel% neq 0 (
    echo No JAR files found in build/libs/
)

echo.
echo To run the JAR file, use:
echo java -jar build/libs/[jar-filename].jar
echo.

pause
