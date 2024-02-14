#define _CRT_SECURE_NO_WARNINGS
#include "main.h"
#include "structs.h"


/*------------------------
 Read the shellcode from
 disk
-------------------------*/
BOOL ReadF(const char* file_path, PDWORD file_size, PVOID* read_buffer) {
	FILE* file;

	file = fopen(file_path, "rb");
	if (file == NULL) {
		DEBUG_PRINT("[!] Error opening file: %s", file_path);
		*file_size = 0;
		return FALSE;
	}

	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	rewind(file);

	*read_buffer = (char*)malloc(*file_size);
	if (*read_buffer == NULL) {
		DEBUG_PRINT("[!] Memory allocation failed");
		fclose(file);
		return FALSE;
	}

	fread(*read_buffer, 1, *file_size, file);
	DEBUG_PRINT("[*] Reading shellcode from disk with size: %d\n", *file_size);
	fclose(file);
	return TRUE;
}


BOOL GetSC(PCONTENT cnt) {

	if (!ReadF(LOCAL_FILE, &(cnt->size), &(cnt->data))) {
		DEBUG_PRINT("[!] Failed reading the shellcode from disk.\n");
		return FALSE;
	}
	return TRUE;
}