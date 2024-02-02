#include <stdlib.h>
#include <windows.h>
#include <stdio.h>
/*
Custom implementations of: 
1 - GetProcAddress
2 - GetModuleHandle
Both functions work with hashed strings, trough JenkinsOneAtATime32Bit
Ref: https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringJenkinsOneAtATime32Bit.cpp
*/

#define INITIAL_SEED 8


//Struct definitions
typedef
VOID
(PS_POST_PROCESS_INIT_ROUTINE)(
    VOID
    );
typedef PS_POST_PROCESS_INIT_ROUTINE* PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _ACTIVATION_CONTEXT {
    ULONG   cbSize;   
    DWORD   dwFlags;       
    LPCTSTR lpSource;     
    USHORT  wProcessorArchitecture; 
    LANGID  wLangId;               
    LPCTSTR lpAssemblyDirectory;   
    LPCTSTR lpResourceName;        
    LPCTSTR lpApplicationName;      

} ACTIVATION_CONTEXT, * PACTIVATION_CONTEXT;


typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PACTIVATION_CONTEXT EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


//Hash functions definition
//ASCI string
UINT32 HashA(PCHAR String)
{
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = lstrlenA(String);

    while (Index != Length)
    {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

/*
//Wide char input string
UINT32 HashW(PWCHAR String)
{
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = lstrlenW(String);

    while (Index != Length)
    {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}


//Function to handle different case in DLL names
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

    WCHAR lStr1[MAX_PATH], lStr2[MAX_PATH];
    int len1 = lstrlenW(Str1), len2 = lstrlenW(Str2);
    int i = 0, j = 0;

    // Checking length. We dont want to overflow the buffers
    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;

    // Converting Str1 to lower case string (lStr1)
    for (i = 0; i < len1; i++) {
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0'; // null terminating

    // Converting Str2 to lower case string (lStr2)
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0'; // null terminating

    // Comparing the lower-case strings
    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;

    return FALSE;
}
*/

//Define our own GetModuleHandle
HMODULE GetHand(UINT32 hashLib) { //LPCWSTR SearchDllName) {
    //printf("Trying to locate PEB\n");

    //Read the PEB address from the GS register trough VS macro
    #ifdef _WIN64 // if compiling as x64
        PPEB pPeb = (PEB*)(__readgsqword(0x60));
    #elif _WIN32 // if compiling as x32
        PPEB pPeb = (PEB*)(__readfsdword(0x30));
    #endif

    //Get the LDR member of the PEB structure
    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    //Get the InMemoryOrderModuleList member
    LIST_ENTRY ModuleList = pLdr->InMemoryOrderModuleList;

    //Get the first entry in the ModuleList
    PLDR_DATA_TABLE_ENTRY pTableEntry = (PLDR_DATA_TABLE_ENTRY)ModuleList.Flink;

    //Parse all entries until the correct lib is found
    while (pTableEntry) {

        if (pTableEntry->FullDllName.Length != NULL) {

            //Convert the lib name to uppercase
            CHAR Upper[MAX_PATH];
            DWORD i = 0;
            while (pTableEntry->FullDllName.Buffer[i]) {
                Upper[i] = (CHAR)toupper(pTableEntry->FullDllName.Buffer[i]);
                i++;
            }
            Upper[i] = '\0';


            //Check if this is our DLL
            //if (IsStringEqual(pTableEntry->FullDllName.Buffer, SearchDllName)) {
            if (HashA(Upper) == hashLib) {
                //printf("Original lib handle: 0x%p\n", GetModuleHandleA("kernel32.dll"));
                wprintf(L"Module %ls found, handle: 0x%p\n", pTableEntry->FullDllName.Buffer, pTableEntry->InInitializationOrderLinks.Flink);
                return (HMODULE)(pTableEntry->InInitializationOrderLinks.Flink);
            }
        }
        else {
            break;
        }

        //Get next element
        pTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pTableEntry);
    }
    return NULL;
}


//Define our own GetProcAddress
FARPROC GetAddr(HMODULE hModule, UINT32 ApiHash) { //LPCSTR ApiName) {
    //Convert the handle to PBYTE for pointer arithmetic
    PBYTE peStart = (PBYTE)hModule;

    //Get the DOS header and verify it
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)peStart;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid DOS header.\n");
        return NULL;
    }

    //Get the NT header and verify it
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(peStart + pDosHdr->e_lfanew);
    if (pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
        printf("No valid NT headers found.\n");
        return NULL;
    }

    //Get the optional headers
    IMAGE_OPTIONAL_HEADER pOptHdr = pNtHdr->OptionalHeader;

    //Get the image export table
    PIMAGE_EXPORT_DIRECTORY pExpTbl = (PIMAGE_EXPORT_DIRECTORY)(peStart + pOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    //Get the addresses of the function names, function addresses and function name ordinals arrays
    PDWORD fnNameArray = (PDWORD)(peStart + pExpTbl->AddressOfNames);
    PDWORD fnAddrArray = (PDWORD)(peStart + pExpTbl->AddressOfFunctions);
    PWORD fnNameOrdinals = (PWORD)(peStart + pExpTbl->AddressOfNameOrdinals);


    //Loop trough the exported functions, NumberOfFunctions is used as a max value
    for (DWORD i = 0; i < pExpTbl->NumberOfFunctions; i++) {
        //pointer to the function's name
        CHAR* pFuncName = (CHAR*)(peStart + fnNameArray[i]);
    
        //Ordinal of the function
        WORD funcOrdinal = fnNameOrdinals[i];

        //Getting the function's address trough its ordinal
        PVOID funcAddr = (PVOID)(peStart + fnAddrArray[funcOrdinal]);

        //Search for the needed function
        //if (strcmp(ApiName, pFuncName) == 0) {
        if (ApiHash == HashA(pFuncName)) {
            //printf("Original func: 0x%p\n", GetProcAddress(hModule, "CreateThread"));
            printf("[ %0.4d ] - Name: %s, Ordinal: %d, Address: 0x%p\n", i, pFuncName, funcOrdinal, funcAddr);
            return funcAddr;
        }
        //printf("[%d] - Name: %s, Ordinal: %d, Address: 0x%p\n", i, pFuncName, funcOrdinal, funcAddr);
    }
    return NULL;
}




int main()
{

    //CreateThread hash : 0xEA8C80C9
    //KERNEL32.DLL hash : 0xE2E3C536
    
    //UINT32 hashFun = 0xEA8C80C9;
    //UINT32 hashLib = 0xFD2AD9BD;

    //FARPROC funcAddr = NULL;
    //HMODULE hModule = NULL;

    //hModule = GetHand(hashLib);
    //funcAddr = GetAddr(hModule, hashFun);

    //CloseHandle(hModule);

    //UINT32 hashFun = HashA("CreateThread");
    //UINT32 hashLib = HashA("KERNEL32.DLL");
    printf("NTDLL.DLL hash: 0x%0.8X\n", HashA("NTDLL.DLL"));
    printf("NtAllocateVirtualMemory hash: 0x%0.8X\n", HashA("NtAllocateVirtualMemory"));
    printf("NtProtectVirtualMemory hash: 0x%0.8X\n", HashA("NtProtectVirtualMemory"));
    printf("NtWriteVirtualMemory hash: 0x%0.8X\n", HashA("NtWriteVirtualMemory"));
    printf("NtCreateThreadEx hash: 0x%0.8X\n", HashA("NtCreateThreadEx"));
    printf("NtOpenProcess hash: 0x%0.8X\n", HashA("NtOpenProcess"));


    return 0;
}
