#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "structs.h"



#define LOCAL_FILE "C:\\Users\\nullb1t3\\Desktop\\calc.bin"


/*------------------------
  Sacrificial DLL
------------------------*/
#define SACRIFICIAL_DLL L"\\??\\C:\\Windows\\System32\\combase.dll"


/*-----------------------
  Debug output
-----------------------*/
#define DEBUG



/*----------------------
  Global variables
----------------------*/
extern NTAPIS NtAPIs;



/*-----------------------------
  Function prototypes
-----------------------------*/
BOOL InitAPIs();
BOOL MapAndCheckDLL(OUT HMODULE hModule, OUT PULONG_PTR dllEntry, IN SIZE_T scSize);
BOOL WriteExec(IN ULONG_PTR dllEntry, IN PCONTENT cnt);


//Read the shellcode from file
BOOL GetSC(PCONTENT cnt);


/*--------------------------------------
 InitializeObjectAttributes Macro
--------------------------------------*/
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

/*--------------------------
  Custom memcpy function
--------------------------*/
static inline void mymemcpy(char* dst, const char* src, int size) {
    int x;
    if (src == NULL) {
        for (x = 0; x < size; x++) {
            *dst = 0x00;
            dst++;
        }
    }
    else {
        for (x = 0; x < size; x++) {
            *dst = *src;
            dst++;
            src++;
        }
    }
}


/*-----------------------------------------
  Simple marcros
-----------------------------------------*/
#ifdef DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#define WDEBUG_PRINT(...) wprintf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) do {} while (0)
#define WDEBUG_PRINT(...) do {} while (0)
#endif