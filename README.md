# LibLoader

A Windows DLL injection utility that allows injecting one or more DLLs into a target executable by creating a suspended process and modifying the entry point.

## Building

### Using Make

The project includes a Makefile with several build targets:

```
# Build both 32-bit and 64-bit versions (default)
make

# Build only 32-bit version
make x86

# Build only 64-bit version
make x64

# Build with MSVC compiler (if available)
make msvc

# Clean build artifacts
make clean
```

### Using VS Code

The project includes VS Code task configurations in `.vscode/tasks.json`. Press `Ctrl+Shift+B` to build using the default task.

## Usage

```
libloader.exe path_to_exe path_to_dll [path_to_dll2] [path_to_dll3] ...
```

### Example

```
libloader32.exe c:\path\to\target.exe c:\path\to\inject.dll
```

## Notes

- The target executable is created in a suspended state
- The DLLs are loaded using `LoadLibraryA`
- Multiple DLLs can be injected in a single command
- The utility works on both 32-bit and 64-bit Windows systems (when compiled appropriately)