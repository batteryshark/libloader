# Test Suite for LibLoader

This directory contains test files to verify the correct operation of the LibLoader DLL injection utility.

## Test Components

- `test_exe_x86.exe` - 32-bit test executable that serves as the injection target
- `test_exe_x64.exe` - 64-bit test executable that serves as the injection target
- `test_dll_x86.dll` - 32-bit test DLL that will be injected
- `test_dll_x64.dll` - 64-bit test DLL that will be injected

## How to Test

The test components can be built using the updated Makefile targets:

```bash
# Build all test components (both 32-bit and 64-bit)
make tests

# Build only 32-bit test components
make test_exe_x86 test_dll_x86

# Build only 64-bit test components
make test_exe_x64 test_dll_x64
```

## Running Tests

The Makefile includes test targets that will print the commands you should run:

```bash
# For 32-bit tests
make test_x86

# For 64-bit tests
make test_x64
```

Then manually run the commands shown to test the injection.

## Expected Output

When the test is successful, you should see:
1. The test executable printing "Test program started. Waiting for DLL injection..."
2. The injected DLL printing "[+] Test DLL (XX-bit) successfully injected!"
3. After a pause, the test executable printing "Test program completed."

If the DLL message doesn't appear between steps 1 and 3, the injection has failed. 