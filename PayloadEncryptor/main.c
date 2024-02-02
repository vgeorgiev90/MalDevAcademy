#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <stdio.h>



/* RC4 encryption */
typedef struct {
    DWORD Length;            //Size of data to be encrypted
    DWORD MaximumLength;     //Max size of data to be encrypted, same as length
    PVOID Buffer;            //Base address of data to be encrypted
} USTRING, * PUSTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Data,
    struct USTRING* Key
    );

/*
    pKey  ->  Encryption key
    pData ->  Pointer to the base address of data to be encrypted
    dwKey ->  Size of the key
    sData ->  Size of the data
*/

BOOL Rc4Enc(PBYTE pKey, PBYTE pData, DWORD dwKey, DWORD sData) {
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
    return TRUE;
};

/* Rc4 enc definitions end */


//Simple XOR obfuscation
VOID XoRing(PBYTE pMessage, size_t sMsg_size, PBYTE key, size_t key_size) {
    for (size_t i = 0; i < sMsg_size; i++) {
        pMessage[i] = pMessage[i] ^ key[i % key_size];
    }
}

//Get XOR key
char* GenKeyFromIP(char ips[][15], size_t count) {
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

int WriteF(const char* file_path, const void* data, size_t size) {
    FILE* file;

    file = fopen(file_path, "wb");
    if (file == NULL) {
        printf("Error opening file: %s", file_path);
        return 1;
    }

    if (fwrite(data, 1, size, file) != size) {
        printf("File write failed..");
        fclose(file);
        return 1;
    }
    fclose(file);
    return 0;
}




int main(int argc, char* argv[])
{
    // Seed for XOR key 
    char ips[][15] = {
        "192.168.100.52",
        "10.10.10.12",
        "172.16.132.123",
        "152.77.83.151"
    };

    if (argc < 3) {
        printf("Not enough arguments!\nARG1 -> Source file path to be encrypted\nARG2 -> Destination file path to write encrypted data");
        return 1;
    }

    long file_size;
    char* fileContent;

    printf("Reading file: %s\n", argv[1]);
    ReadF(argv[1], &file_size, &fileContent);

    // Get the XOR key
    char* key = GenKeyFromIP(ips, sizeof(ips) / sizeof(ips[0]));
    // 64 bytes with a null at the end
    char enc_key[] = { 0x4e,0x62,0x51,0x25,0x3a,0x53,0x4a,0x3b,0x5d,0x7b,0x6b,0x21,0x57,0x75,0x4b,0x72,0x3a,0x68,0x21,0x38,0x4a,0x25,0x34,0x40,0x46,0x58,0x61,0x79,0x4d,0x71,0x57,0x21,0x7d,0x62,0x56,0x5d,0x48,0x23,0x5d,0x4e,0x61,0x5d,0x32,0x71,0x45,0x69,0x5b,0x52,0x7d,0x61,0x4a,0x34,0x2f,0x2a,0x3a,0x45,0x35,0x32,0x25,0x2b,0x2c,0x69,0x54,0x00 };
    // Xoring the encryption key
    printf("XORing the encryption key.\n");
    XoRing(enc_key, sizeof(enc_key), key, strlen(key));
    // Encrypting the content
    printf("Doing some magick.\n");
    Rc4Enc(&enc_key, fileContent, strlen(enc_key), (DWORD)file_size);

    printf("Writing data to: %s", argv[2]);
    WriteF(argv[2], fileContent, file_size);
    free(fileContent);

    return 0;
}