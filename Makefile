# Makefile for libloader
# Supports both 32-bit and 64-bit Windows builds

# Compiler settings
CC_x86 = i686-w64-mingw32-gcc
CC_x64 = x86_64-w64-mingw32-gcc
# For Microsoft compiler (alternative)
# CC = cl

# Compiler flags
CFLAGS = -Wall -O2 -fshort-wchar -static -static-libgcc

# Output files
OUT_x86 = libloader32.exe
OUT_x64 = libloader64.exe

# Test output files
TEST_EXE_x86 = test/bin/test_exe_x86.exe
TEST_EXE_x64 = test/bin/test_exe_x64.exe
TEST_DLL_x86 = test/bin/test_dll_x86.dll
TEST_DLL_x64 = test/bin/test_dll_x64.dll

# Default target
all: x86 x64

# Build all (including tests)
all_with_tests: all tests

# 32-bit build
x86:
	$(CC_x86) $(CFLAGS) -m32 libloader.c -o $(OUT_x86)

# 64-bit build
x64:
	$(CC_x64) $(CFLAGS) libloader.c -o $(OUT_x64)

# Test builds
tests: test_exe_x86 test_exe_x64 test_dll_x86 test_dll_x64

# Test executable (32-bit)
test_exe_x86:
	$(CC_x86) $(CFLAGS) -m32 test/src/test_exe.c -o $(TEST_EXE_x86)

# Test executable (64-bit)
test_exe_x64:
	$(CC_x64) $(CFLAGS) test/src/test_exe.c -o $(TEST_EXE_x64)

# Test DLL (32-bit)
test_dll_x86:
	$(CC_x86) $(CFLAGS) -m32 -shared test/src/test_dll.c -o $(TEST_DLL_x86)

# Test DLL (64-bit)
test_dll_x64:
	$(CC_x64) $(CFLAGS) -shared test/src/test_dll.c -o $(TEST_DLL_x64)

# Build with MSVC (if available)
msvc:
	cl /O2 /Fe:libloader_msvc.exe libloader.c

# Test targets
test_x86: x86 test_exe_x86 test_dll_x86
	@echo "Running 32-bit injection test..."
	@echo "Command: $(OUT_x86) $(TEST_EXE_x86) $(TEST_DLL_x86)"

test_x64: x64 test_exe_x64 test_dll_x64
	@echo "Running 64-bit injection test..."
	@echo "Command: $(OUT_x64) $(TEST_EXE_x64) $(TEST_DLL_x64)"

# Clean build outputs
clean:
	del *.exe *.obj 2>nul || (exit 0)
	del test\bin\*.exe test\bin\*.dll 2>nul || (exit 0)

.PHONY: all all_with_tests x86 x64 msvc clean tests test_exe_x86 test_exe_x64 test_dll_x86 test_dll_x64 test_x86 test_x64 