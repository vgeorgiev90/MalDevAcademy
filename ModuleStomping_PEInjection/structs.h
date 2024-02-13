#pragma once
#include <windows.h>



#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_OPEN 0x00000001




/*-----------------------------
  Struct to hold the shellcode
-----------------------------*/
typedef struct _CONTENT {
    LPVOID data;
    DWORD size;
} CONTENT, * PCONTENT;


/*------------------------
  Generic structures
------------------------*/
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


typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;


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



/*--------------------------
  NTAPI function prototypes
--------------------------*/
typedef NTSTATUS(NTAPI* fnNtCreateSection)(
    OUT          PHANDLE            SectionHandle,
    IN           ACCESS_MASK        DesiredAccess,
    IN OPTIONAL  POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL  PLARGE_INTEGER     MaximumSize,
    IN           ULONG              SectionPageProtection,
    IN           ULONG              AllocationAttributes,
    IN OPTIONAL  HANDLE             FileHandle
    );

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
    IN HANDLE               SectionHandle,
    IN HANDLE               ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG                ZeroBits,
    IN ULONG                CommitSize,
    IN OUT PLARGE_INTEGER   SectionOffset,
    IN OUT PULONG           ViewSize,
    IN SECTION_INHERIT      InheritDisposition,
    IN ULONG                AllocationType,
    IN ULONG                Protect
    );

typedef NTSTATUS(NTAPI* fnNtCreateFile)(
    OUT          PHANDLE            FileHandle,
    IN           ACCESS_MASK        DesiredAccess,
    IN           POBJECT_ATTRIBUTES ObjectAttributes,
    OUT          PIO_STATUS_BLOCK   IoStatusBlock,
    IN OPTIONAL  PLARGE_INTEGER     AllocationSize,
    IN           ULONG              FileAttributes,
    IN           ULONG              ShareAccess,
    IN           ULONG              CreateDisposition,
    IN           ULONG              CreateOptions,
    IN           PVOID              EaBuffer,
    IN           ULONG              EaLength
    );


typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PUSER_THREAD_START_ROUTINE StartRoutine,
    IN OPTIONAL PVOID Argument,
    IN ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList
    );

typedef NTSTATUS(NTAPI* fnNtClose)(
    IN HANDLE Handle
    );


typedef NTSTATUS(NTAPI* fnNtWaitForSingleObject)(
    IN HANDLE         Handle,
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER Timeout
    );

/*-------------------------
 Struct to hold the NTAPIs
-------------------------*/
typedef struct _NTAPIS {
    fnNtCreateFile pNtCreateFile;
    fnNtCreateSection pNtCreateSection;
    fnNtMapViewOfSection pNtMapViewOfSection;
    fnNtProtectVirtualMemory pNtProtectVirtualMemory;
    fnNtCreateThreadEx pNtCreateThreadEx;
    fnNtClose pNtClose;
    fnNtWaitForSingleObject pNtWaitForSingleObject;
    BOOL IsInitialized;
}NTAPIS, * PNTAPIS;