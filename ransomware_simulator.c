#include <stdio.h>
#include <windows.h>
#include <string.h>

int main() {
    printf("===========================================\n");
    printf("   BEHAVIORSHIELD REAL-TIME SIMULATOR (.EXE)\n");
    printf("===========================================\n");

    const char* target_dir = "C:\\BehaviorShield\\TestFolder\\RansomTest";
    
    // 1. Create target folder
    CreateDirectoryA("C:\\BehaviorShield", NULL);
    CreateDirectoryA("C:\\BehaviorShield\\TestFolder", NULL);
    CreateDirectoryA(target_dir, NULL);

    // 2. Create 15 mock documents
    printf("[*] Preparing 15 mock documents...\n");
    char path[512];
    for (int i = 0; i < 15; i++) {
        sprintf(path, "%s\\document_%d.txt", target_dir, i);
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "Highly important document content payload. Do not delete or modify. Encryption simulation target. %d", i);
            fclose(f);
        }
    }
    printf("[+] Mock documents created successfully.\n");
    printf("[*] Stabilizing system. Starting encryption sequence in 2 seconds...\n");
    Sleep(2000);

    // 3. Perform rapid renames to trigger EDR rule blocks
    printf("[!] Triggering mass extension encryption (.locked)...\n");
    for (int i = 0; i < 15; i++) {
        char old_path[512];
        char new_path[512];
        sprintf(old_path, "%s\\document_%d.txt", target_dir, i);
        sprintf(new_path, "%s\\document_%d.locked", target_dir, i);
        
        printf("    -> Encrypting file %d/15...\n", i + 1);
        if (rename(old_path, new_path) != 0) {
            printf("[X] Access Denied or Process Blocked at file %d!\n", i + 1);
            break;
        }
        Sleep(50); // slight sleep simulating disk write delay
    }

    printf("[-] End of execution loop.\n");
    return 0;
}
