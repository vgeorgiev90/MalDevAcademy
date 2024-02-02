#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <stdint.h>

//Trampoline size
#ifdef _M_X64
    #define TSIZE 13
#endif


typedef INT(WINAPI* myMsg)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

myMsg g_pMessageBoxA = MessageBoxA;

INT WINAPI myMessage(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("[+] Original Parameters : \n");
    printf("\t - lpText	: %s\n", lpText);
    printf("\t - lpCaption	: %s\n", lpCaption);
    printf("You GOT HOOKED\n");
    //return g_pMessageBoxA(hWnd, "Hooked function", "HOOK", uType);
    return MessageBoxW(hWnd, L"HOOKED madafaka", L"HOOK", uType);
}


typedef struct _HOOK{
    PVOID funToHook;
    PVOID funToCall;
    BYTE originalBytes[TSIZE];
    DWORD oldProtect;
} HOOK, *PHOOK;


BOOL InitHook(IN PVOID pfunToHook, IN PVOID pfunToCall, OUT PHOOK Hook) {
    Hook->funToHook = pfunToHook;
    Hook->funToCall = pfunToCall;

    //Save the original bytes
    memcpy(Hook->originalBytes, pfunToHook, TSIZE);

    if (!VirtualProtect(pfunToHook, TSIZE, PAGE_EXECUTE_READWRITE, &Hook->oldProtect)) {
        printf("VirtualProtect failed with: %d\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}


BOOL UnpatchApi(IN PHOOK hook) {
    memcpy(hook->funToHook, hook->originalBytes, TSIZE);
    if (!VirtualProtect(hook->funToHook, TSIZE, hook->oldProtect, &hook->oldProtect)) {
        printf("VirtualProtect failed with: %d\n", GetLastError());
        return FALSE;
    }
    hook->funToHook = NULL;
    hook->funToCall = NULL;
    hook->oldProtect = NULL;
    return TRUE;
}


BOOL PatchApi(IN PHOOK hook) {
#ifdef _M_X64
    uint8_t uHook[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
        0x41, 0xFF, 0xE2                                            // jmp r10
    };

    uint64_t patch = (uint64_t)(hook->funToCall);
    memcpy(&uHook[2], &patch, sizeof(patch)); // copying the address to the offset '2' in uHook

    /*
    size_t uHookSize = sizeof(uHook) / sizeof(uHook[0]);
    printf("uHook Content:\n");
    for (size_t i = 0; i < uHookSize; i++) {
        printf("%02X ", uHook[i]);
    }
    printf("\n");
    printf("myFunc: 0x%p\n", (uint64_t)(hook->funToCall));
    */

#endif
#ifdef _M_IX86
    uint8_t	uTrampoline[] = {
       0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, pFunctionToRun
       0xFF, 0xE0                        // jmp eax
    };

    uint32_t patch = (uint32_t)(hook->funToCall); // copying the address to the offset '1' in uHook
    memcpy(&uHook[1], &patch, sizeof(patch));
#endif

    //Copy the hook shellcode
    memcpy(hook->funToHook, uHook, sizeof(uHook));

    return TRUE;
}






int main()
{
    HOOK hook = { 0 };

    printf("Press ENTER to init the hook\n");
    getchar();
    if (!InitHook(&MessageBoxA, &myMessage, &hook)) {
        return 1;
    }

    //original
    MessageBoxA(NULL, "This is the original", "Original Box", MB_OK | MB_ICONQUESTION);

    printf("Press ENTER to install the hook\n");
    getchar();
    //hooking
    if (!PatchApi(&hook)) {
        return 1;
    }

    printf("Calling hooked function\n");
    //hooked
    MessageBoxA(NULL, "Test message for hooked fun", "HOOK TEST", MB_OK | MB_ICONWARNING);

    printf("Press ENTER to uninstall the hook\n");
    getchar();
    //unhooking
    if (!UnpatchApi(&hook)) {
        return 1;
    }

    //unhooked
    MessageBoxA(NULL, "Again the unhooked fun", "Unhooked Box", MB_OK | MB_ICONQUESTION);

    return 0;
}

