@echo off
REM ======================================================================
REM Build script for the Syscall Engine Framework
REM This script requires the x64 Native Tools Command Prompt for VS
REM ======================================================================

echo [*] Step 1: Generating polymorphic syscall stubs...
REM Use Py or Python depending on your installation
py generate_stubs.py
if %errorlevel% neq 0 (
    echo [!] Python script failed. Make sure Python is installed and added to PATH.
    exit /b %errorlevel%
)

echo [*] Step 2: Assembling syscalls.asm...
ml64 /c /Cx /nologo syscalls.asm
if %errorlevel% neq 0 (
    echo [!] Assembly failed. Check syntax errors in ASM file.
    exit /b %errorlevel%
)

echo [*] Step 3: Compiling C source files and linking...
REM /O2 optimizes for speed
REM /CETCOMPAT:NO disables Control-flow Enforcement Technology to allow stack spoofing
cl /nologo /O2 main.c engine.c syscalls.obj /Fe:TestFramework.exe /link /CETCOMPAT:NO /SUBSYSTEM:CONSOLE
if %errorlevel% neq 0 (
    echo [!] Compilation failed. Check C source code for errors.
    exit /b %errorlevel%
)

echo [+] Build successful: TestFramework.exe

REM Clean up intermediate object and generated ASM files (optional)
del *.obj >nul 2>&1
REM del syscalls.asm >nul 2>&1