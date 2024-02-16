#pragma once
#include "main.h"
#include <windows.h>
#include <winternl.h>


#define RTL_MAX_DRIVE_LETTERS 32


/*-----------------------------
  Struct to hold the shellcode
-----------------------------*/
typedef struct _CONTENT {
    LPVOID data;
    DWORD size;
} CONTENT, * PCONTENT;


/*--------------------------
 Struct to hold the parsed
 headers of the PE
--------------------------*/
typedef struct _PEHDRS {
    PBYTE pPeBuffer;
    DWORD PeSize;

    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_SECTION_HEADER pSectHeader;

    PIMAGE_DATA_DIRECTORY pImportDir;
    PIMAGE_DATA_DIRECTORY pRelocDir;
    PIMAGE_DATA_DIRECTORY pTslDir;
    PIMAGE_DATA_DIRECTORY pExportDir;
    PIMAGE_DATA_DIRECTORY pExceptDir;

    BOOL IsDLL;

}PEHDRS, * PPEHDRS;


/*------------------------------
  Generic structs 
------------------------------*/
typedef struct _USTRING {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} USTRING, * PUSTRING;

/*
typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;


typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING, UNICODE_STRING, * PUNICODE_STRING, * PUSTRING;


typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    PVOID RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, * PCURDIR;


typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;

	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

	UNICODE_STRING RedirectionDllName;
	UNICODE_STRING HeapPartitionName;
	ULONG_PTR DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
	ULONG DefaultThreadpoolThreadMaximum;
	ULONG HeapMemoryTypeMask;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID*					KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID*					ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID**					ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;

*/

/*-------------------------------
  Function prototypes
-------------------------------*/
typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
    );


typedef NTSTATUS(NTAPI* fnNtClose)(
    IN HANDLE Handle
    );

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN ULONG BufferLength,
    OUT PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
    IN      HANDLE    ProcessHandle,
    OUT     PVOID* BaseAddress,
    IN      ULONG_PTR ZeroBits,
    OUT     PSIZE_T   RegionSize,
    IN      ULONG     AllocationType,
    IN      ULONG     Protect
    );

typedef NTSTATUS(NTAPI* fnNtGetContextThread)(
    IN HANDLE               ThreadHandle,
    OUT PCONTEXT            pContex
    );

typedef NTSTATUS(NTAPI* fnNtSetContextThread)(
    IN HANDLE               ThreadHandle,
    IN PCONTEXT             Context
    );

typedef NTSTATUS(NTAPI* fnNtResumeThread)(
    IN HANDLE               ThreadHandle,
    OUT PULONG              SuspendCount
    );

typedef NTSTATUS(NTAPI* fnNtWaitForSingleObject)(
    IN HANDLE         Handle,
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER Timeout
    );


typedef NTSTATUS(NTAPI* fnNtReadVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded
	);


//SystemFunction032
typedef NTSTATUS(NTAPI* fnSF032)(
    struct UNICODE_STRING* Data,
    struct UNICODE_STRING* Key
    );

/*-------------------------
 Struct to hold the NTAPIs
-------------------------*/
typedef struct _NTAPIS {
    fnNtProtectVirtualMemory pNtProtectVirtualMemory;
    fnNtClose pNtClose;
    fnNtAllocateVirtualMemory pNtAllocateVirtualMemory;
    fnNtWriteVirtualMemory pNtWriteVirtualMemory;
    fnNtGetContextThread pNtGetContextThread;
    fnNtSetContextThread pNtSetContextThread;
    fnNtResumeThread pNtResumeThread;
    fnNtWaitForSingleObject pNtWaitForSingleObject;
	fnNtReadVirtualMemory pNtReadVirtualMemory;
    BOOL IsInitialized;
}NTAPIS, * PNTAPIS;