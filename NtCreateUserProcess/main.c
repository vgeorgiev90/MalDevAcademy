#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include "main.h"




BOOL CreateProc(DWORD pPid, PWSTR procImage, PWSTR procCWD, PWSTR procCL, PHANDLE hProcess, PHANDLE hThread) {

    HMODULE hModule = LoadLibraryW(L"ntdll.dll");
    if (hModule == NULL) {
        printf("Failed loading library\n");
        return FALSE;
    }

    fnNtCreateUserProcess Creater = (fnNtCreateUserProcess)GetProcAddress(hModule, "NtCreateUserProcess");
    fnRtlCreateProcessParametersEx CreateParams = (fnRtlCreateProcessParametersEx)GetProcAddress(hModule, "RtlCreateProcessParametersEx");
    fnNtOpenProcess OpenP = (fnNtOpenProcess)GetProcAddress(hModule, "NtOpenProcess");
    if (Creater == NULL || CreateParams == NULL || OpenP == NULL) {
        printf("Failed getting addresses\n");
        return FALSE;
    }

    DWORD64 mPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    NTSTATUS status = NULL;
    UNICODE_STRING NtPath = { 0 },
        NtCWD = { 0 },
        NtCL = { 0 };
    PRTL_USER_PROCESS_PARAMETERS pProcParams = NULL;
    PPS_ATTRIBUTE_LIST pAttrList = (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    if (!pAttrList) {
        printf("Failed allocating memory\n");
        return FALSE;
    }

    //Unicode strings initializations
    NtPath.Buffer = procImage;
    NtPath.Length = wcslen(NtPath.Buffer) * sizeof(WCHAR);
    NtPath.MaximumLength = NtPath.Length + sizeof(WCHAR);

    NtCWD.Buffer = procCWD;
    NtCWD.Length = wcslen(NtCWD.Buffer) * sizeof(WCHAR);
    NtCWD.MaximumLength = NtCWD.Length + sizeof(WCHAR);

    NtCL.Buffer = procCL;
    NtCL.Length = wcslen(NtCL.Buffer) * sizeof(WCHAR);
    NtCL.MaximumLength = NtCL.Length + sizeof(WCHAR);


    //RTL_USER_PROCESS_PARAMETERS initialization
    status = CreateParams(&pProcParams, &NtPath, NULL, &NtCWD, &NtCL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
    if (status != 0x00) {
        printf("Parameter creation failed: 0x%X\n", status);
        goto _Cleanup;
    }
    printf("Param create: 0x%X\n", status);


    //PROCESS ATTRIBUTES initialization
    pAttrList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
    //Process Image 
    pAttrList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    pAttrList->Attributes[0].Size = NtPath.Length;
    pAttrList->Attributes[0].Value = (ULONG_PTR)NtPath.Buffer;

    //Block DLL policy
    pAttrList->Attributes[1].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
    pAttrList->Attributes[1].Size = sizeof(DWORD64);
    pAttrList->Attributes[1].Value = &mPolicy;

    //Process Parrent proc
    HANDLE hParrent = NULL;
    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)pPid; 
    cid.UniqueThread = (HANDLE)0;
    OBJECT_ATTRIBUTES oAttr = { 0 };
    InitializeObjectAttributes(&oAttr, NULL, 0, NULL, NULL);

    status = OpenP(&hParrent, PROCESS_ALL_ACCESS, &oAttr, &cid);
    if (status != 0x00) {
        printf("Failed opening parent process: 0x%X\n", status);
        goto _Cleanup;
    }
    printf("Parent handle: 0x%X\n", hParrent);
    pAttrList->Attributes[2].Attribute = PS_ATTRIBUTE_PARRENT_PROCESS;
    pAttrList->Attributes[2].Size = sizeof(HANDLE);
    pAttrList->Attributes[2].Value = hParrent;




    //Create info struct
    PS_CREATE_INFO procInfo = {
        .Size = sizeof(PS_CREATE_INFO),
        .State = PsCreateInitialState
    };

    //Create the process
    status = Creater(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, pProcParams, &procInfo, pAttrList);
    if (status != 0x00) {
        printf("Process creation failed: 0x%X\n", status);
        goto _Cleanup;
    }
    printf("Process create: 0x%X\n", status);
    return TRUE;


_Cleanup:
    HeapFree(GetProcessHeap(), 0 , pAttrList);
    return FALSE;
}




int main()
{
    PWSTR procImage = L"\\??\\C:\\Windows\\System32\\cmd.exe";
    PWSTR cwd = L"C:\\Windows\\System32";
    PWSTR cLine = L"C:\\Windows\\System32\\cmd.exe";
    DWORD ppid = 784;

    HANDLE hProcess = NULL, hThread = NULL;

    if (!CreateProc(ppid, procImage, cwd, cLine, &hProcess, &hThread)) {
        printf("[!] Failed creating process.\n");
        return 1;
    }


    printf("Process created:\nPID: %d\nTID: %d\n", GetProcessId(hProcess), GetThreadId(hThread));


    return 0;
}

