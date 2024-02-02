#pragma once
#include <windows.h>




/*------------------------------
 Struct definitions
------------------------------*/
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING, UNICODE_STRING, * PUNICODE_STRING, * PUSTRING;


typedef LONG  KPRIORITY;

typedef struct __CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


typedef enum _KTHREAD_STATE
{
    Initialized = 0,
    Ready = 1,
    Running = 2,
    Standby = 3,
    Terminated = 4,
    Waiting = 5,
    Transition = 6,
    DeferredReady = 7,
    GateWait = 8
} KTHREAD_STATE;


typedef enum _KWAIT_REASON
{
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4,
    Suspended = 5,
    UserRequest = 6,
    WrExecutive = 7,
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,
    WrSuspended = 12,
    WrUserRequest = 13,
    WrEventPair = 14,
    WrQueue = 15,
    WrLpcReceive = 16,
    WrLpcReply = 17,
    WrVirtualMemory = 18,
    WrPageOut = 19,
    WrRendezvous = 20,
    Spare2 = 21,
    Spare3 = 22,
    Spare4 = 23,
    Spare5 = 24,
    WrCalloutStack = 25,
    WrKernel = 26,
    WrResource = 27,
    WrPushLock = 28,
    WrMutex = 29,
    WrQuantumEnd = 30,
    WrDispatchInt = 31,
    WrPreempted = 32,
    WrYieldExecution = 33,
    WrFastMutex = 34,
    WrGuardedMutex = 35,
    WrRundown = 36,
    MaximumWaitReason = 37
} KWAIT_REASON;


typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG ContextSwitches;
    KTHREAD_STATE ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads; // Size of the Threads member
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1]; // Threads member
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    PVOID RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef enum _PROCESSINFOCLASS {
    ProcessSessionInformation = 24,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, * PPROCESSINFOCLASS;


typedef struct _PROCESS_SESSION_INFORMATION
{
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION, * PPROCESS_SESSION_INFORMATION;


typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;


typedef struct _HIJACK {
    DWORD PID;
    DWORD TID;
}HIJACK, * PHIJACK;

/*-----------------------------
  Function prototypes
-----------------------------*/
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
    IN            SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT        PVOID                    SystemInformation,
    IN            ULONG                    SystemInformationLength,
    OUT OPTIONAL  PULONG                   ReturnLength
    );


typedef NTSTATUS(NTAPI* fnNtGetContextThread)(
    IN HANDLE               ThreadHandle,
    OUT PCONTEXT            pContex
    );

typedef NTSTATUS(NTAPI* fnNtSetContextThread)(
    IN HANDLE               ThreadHandle,
    IN PCONTEXT             Context
    );

typedef NTSTATUS(NTAPI* fnNtOpenThread)(
    OUT PHANDLE            ThreadHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  PCLIENT_ID         ClientId
    );

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    IN            HANDLE           ProcessHandle,
    IN            PROCESSINFOCLASS ProcessInformationClass,
    OUT           PVOID            ProcessInformation,
    IN            ULONG            ProcessInformationLength,
    OUT OPTIONAL  PULONG           ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtSuspendThread)(
    IN HANDLE               ThreadHandle,
    OUT PULONG              PreviousSuspendCount
    );

typedef NTSTATUS(NTAPI* fnNtResumeThread)(
    IN HANDLE               ThreadHandle,
    OUT PULONG              SuspendCount
    );

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

typedef NTSTATUS(NTAPI* fnNtOpenProcess)(
    OUT          PHANDLE            ProcessHandle,
    IN           ACCESS_MASK        DesiredAccess,
    IN           POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL  PCLIENT_ID         ClientId
    );

typedef NTSTATUS(NTAPI* fnNtClose)(
    IN HANDLE Handle
    );


typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
    IN HANDLE               ProcessHandle,         
    IN PVOID                BaseAddress,            
    IN PVOID                Buffer,                 
    IN ULONG                NumberOfBytesToWrite,   
    OUT PULONG              NumberOfBytesWritten
    );


typedef struct _NTAPIS {
    fnNtQuerySystemInformation pNtQuerySystemInformation;
    fnNtGetContextThread pNtGetContextThread;
    fnNtSetContextThread pNtSetContextThread;
    fnNtOpenThread pNtOpenThread;
    fnNtQueryInformationProcess pNtQueryInformationProcess;
    fnNtSuspendThread pNtSuspendThread;
    fnNtResumeThread pNtResumeThread;
    fnNtCreateSection pNtCreateSection;
    fnNtMapViewOfSection pNtMapViewOfSection;
    fnNtOpenProcess pNtOpenProcess;
    fnNtClose pNtClose;
    fnNtWriteVirtualMemory pNtWriteVirtualMemory;
}NTAPIS, * PNTAPIS;



#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif


void mymemcpy(char* dst, const char* src, int size) {
    int x;
    for (x = 0; x < size; x++) {
        *dst = *src;
        dst++;
        src++;
    }
}