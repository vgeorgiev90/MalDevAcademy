#include <stdlib.h>
#include <windows.h>
#include <stdio.h>

#define HASH_SEED 8


DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x77347734DEADBEEF; //0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

UINT32 HashA(PCHAR String)
{
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = lstrlenA(String);

    while (Index != Length)
    {
        Hash += String[Index++];
        Hash += Hash << HASH_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

int main()
{
	printf("#define %s%s 0x%X\n", "NtAllocateVirtualMemory", "_H", HashA("NtAllocateVirtualMemory"));
	printf("#define %s%s 0x%X\n", "NtProtectVirtualMemory", "_H", HashA("NtProtectVirtualMemory"));
	printf("#define %s%s 0x%X\n", "NtWriteVirtualMemory", "_H", HashA("NtWriteVirtualMemory"));
	printf("#define %s%s 0x%X\n", "NtCreateThreadEx", "_H", HashA("NtCreateThreadEx"));
	printf("#define %s%s 0x%X\n", "NtOpenProcess", "_H", HashA("NtOpenProcess"));
	printf("#define %s%s 0x%X\n", "NtWaitForSingleObject", "_H", HashA("NtWaitForSingleObject"));
    printf("#define %s%s 0x%X\n", "NtCreateFile", "_H", HashA("NtCreateFile"));
    printf("#define %s%s 0x%X\n", "NtClose", "_H", HashA("NtClose"));
    printf("#define %s%s 0x%X\n", "NtCreateSection", "_H", HashA("NtCreateSection"));
    printf("#define %s%s 0x%X\n", "NtMapViewOfSection", "_H", HashA("NtMapViewOfSection"));
    printf("#define %s%s 0x%X\n", "NtUnmapViewOfSection", "_H", HashA("NtUnmapViewOfSection"));
    printf("#define %s%s 0x%X\n", "NtOpenFile", "_H", HashA("NtOpenFile"));
    printf("#define %s%s 0x%X\n", "NtOpenSection", "_H", HashA("NtOpenSection"));
    printf("#define %s%s 0x%X\n", "NtReadFile", "_H", HashA("NtReadFile"));
    printf("#define %s%s 0x%X\n", "NtQueryInformationProcess", "_H", HashA("NtQueryInformationProcess"));
    printf("#define %s%s 0x%X\n", "NtQuerySystemInformation", "_H", HashA("NtQuerySystemInformation"));
    printf("#define %s%s 0x%X\n", "NtSetInformationFile", "_H", HashA("NtSetInformationFile"));
    printf("\n");
    printf("#define %s%s 0x%X\n", "EtwpEventWriteFull", "_H", HashA("EtwpEventWriteFull"));
    printf("\n");


    //printf("0x%X", HashA("LoadLibraryA"));
    return 0;
}


