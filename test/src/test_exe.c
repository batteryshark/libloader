#include <stdio.h>
#include <windows.h>

int main() {
    printf("Test program started. Waiting for DLL injection...\n");
    
    // Wait for a bit to allow time for injection
    Sleep(5000);
    
    printf("Test program completed. If no DLL message appeared, injection failed.\n");
    return 0;
} 