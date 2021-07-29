#include <Windows.h>
#include <stdio.h>
#include <string.h>



void createShellcode(int ret, HANDLE hProcess, int argc, char* argv[], LPVOID* shellcode, int* shellcodeSize){
    FARPROC lla_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    unsigned char llaChar[4] = {0x00};
    memcpy(llaChar,(unsigned char*)&lla_addr,4);
    unsigned char* retChar = (unsigned char*)&ret;
    unsigned char* shellcode_data = (unsigned char*)malloc(*shellcodeSize);
    
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

    // Precalculate shellcode size for all libraries.
    int num_libs = argc - 2;
    *shellcodeSize = sizeof(shellcode_prologue) + sizeof(shellcode_epilogue) + (num_libs * sizeof(shellcode_call));
    // Allocate Memory for Shellcode
    *shellcode = VirtualAllocEx(hProcess, NULL, *shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    // Create and Write Prologue.
    LPVOID current_offset = shellcode_data;

    memcpy(shellcode_prologue+1,retChar,4);
    memcpy(current_offset,shellcode_prologue,sizeof(shellcode_prologue));
    current_offset+=sizeof(shellcode_prologue);


    memcpy(shellcode_call+6,llaChar,4);

    for(int i = 2; i < argc; i++){
        LPVOID library_name_ptr = VirtualAllocEx(hProcess, NULL, strlen(argv[i])+1, MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(hProcess, library_name_ptr, argv[i], strlen(argv[i]), NULL);
        unsigned char* libChar = (unsigned char*)&library_name_ptr;
        memcpy(shellcode_call+1,libChar,4);
        memcpy(current_offset,shellcode_call,sizeof(shellcode_call));
        current_offset+=sizeof(shellcode_call);        
    }

    memcpy(current_offset,shellcode_epilogue,sizeof(shellcode_epilogue));
    WriteProcessMemory(hProcess, *shellcode, shellcode_data,*shellcodeSize, NULL);
   
}

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
    char* full_exe_path = calloc(1,4096);
    GetFullPathName(argv[1], 4096, full_exe_path, NULL);

    // Get the Full DLL Path for our injection.
    char* exe_base_path = (char*)malloc(1024);
    GetDirectoryPath(exe_base_path,full_exe_path, 1024);


    // Create Process SUSPENDED
    PROCESS_INFORMATION pi;
    STARTUPINFOA Startup;
    ZeroMemory(&Startup, sizeof(Startup));
    ZeroMemory(&pi, sizeof(pi));

    CreateProcessA(full_exe_path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, exe_base_path, &Startup, &pi);
    free(exe_base_path);

    ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(pi.hThread, &ctx);

    createShellcode(ctx.Eip,pi.hProcess,argc,argv, &shellcode, &shellcodeLen);
   
    


    // Set EIP To Shellcode
    ctx.Eip = (DWORD)shellcode;
    ctx.ContextFlags = CONTEXT_CONTROL;
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);

    Sleep(800); // Might want to turn this down... 8 seconds is a lot.

    if(shellcode){
#pragma warning(suppress: 28160)
#pragma warning(suppress: 6250)
        VirtualFreeEx(pi.hProcess, shellcode, shellcodeLen, MEM_DECOMMIT);
    }

    return 0;
}