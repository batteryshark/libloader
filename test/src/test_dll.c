#include <windows.h>
#include <stdio.h>

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Create a console if needed
            AllocConsole();
            FILE* file;
            freopen_s(&file, "CONOUT$", "w", stdout);
            
            // Print injection success message with architecture info
#ifdef _WIN64
            printf("[+] Test DLL (64-bit) successfully injected!\n");
#else
            printf("[+] Test DLL (32-bit) successfully injected!\n");
#endif
            break;
            
        case DLL_PROCESS_DETACH:
            break;
            
        case DLL_THREAD_ATTACH:
            break;
            
        case DLL_THREAD_DETACH:
            break;
    }
    
    return TRUE;
} 