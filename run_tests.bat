@echo off
echo LibLoader Test Suite
echo =================

echo.
echo Checking for available test files...

set RUN_COUNT=0

if exist "libloader64.exe" (
    if exist "test\bin\test_exe_x64.exe" (
        if exist "test\bin\test_dll_x64.dll" (
            echo.
            echo Running 64-bit test...
            echo.
            libloader64.exe test\bin\test_exe_x64.exe test\bin\test_dll_x64.dll
            set /a RUN_COUNT+=1
        ) else (
            echo Warning: Missing test_dll_x64.dll, cannot run 64-bit test.
        )
    ) else (
        echo Warning: Missing test_exe_x64.exe, cannot run 64-bit test.
    )
) else (
    echo Warning: Missing libloader64.exe, cannot run 64-bit test.
)

if exist "libloader32.exe" (
    if exist "test\bin\test_exe_x86.exe" (
        if exist "test\bin\test_dll_x86.dll" (
            echo.
            echo Running 32-bit test...
            echo.
            libloader32.exe test\bin\test_exe_x86.exe test\bin\test_dll_x86.dll
            set /a RUN_COUNT+=1
        ) else (
            echo Warning: Missing test_dll_x86.dll, cannot run 32-bit test.
        )
    ) else (
        echo Warning: Missing test_exe_x86.exe, cannot run 32-bit test.
    )
) else (
    echo Warning: Missing libloader32.exe, cannot run 32-bit test.
)

echo.
if %RUN_COUNT% gtr 0 (
    echo Tests completed
) else (
    echo No tests were run! Please check that test files exist.
)
pause 