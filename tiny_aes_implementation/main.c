#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// "this is plaintext string, we'll try to encrypt... lets hope everything goes well :)" in hex
// since the upper string is 82 byte in size, and 82 is not mulitple of 16, we cant encrypt this directly using tiny-aes
unsigned char Data[] = {
	0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x70, 0x6C, 0x61, 0x6E,
	0x65, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x69, 0x6E, 0x67,
	0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74, 0x72, 0x79, 0x20,
	0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x2E, 0x2E,
	0x2E, 0x20, 0x6C, 0x65, 0x74, 0x73, 0x20, 0x68, 0x6F, 0x70, 0x65, 0x20,
	0x65, 0x76, 0x65, 0x72, 0x79, 0x74, 0x68, 0x69, 0x67, 0x6E, 0x20, 0x67,
	0x6F, 0x20, 0x77, 0x65, 0x6C, 0x6C, 0x20, 0x3A, 0x29, 0x00
};

const int KEYSIZE = 32;
const int IVSIZE = 16;


BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE	PaddedBuffer = NULL;
	SIZE_T	PaddedSize = NULL;

	// calculate the nearest number that is multiple of 16 and saving it to PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// allocating buffer of size "PaddedSize"
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer) {
		return FALSE;
	}
	// cleaning the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);
	// copying old buffer to new padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	//saving results :
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize = PaddedSize;

	return TRUE;
}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		} else {
			printf("0x%0.2X ", Data[i]);
		}

		printf("};\n\n\n");

}

VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {
	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}
}

int main() {
	// struct needed for Tiny-AES library
	struct AES_ctx ctx;


	BYTE pKey[32];                             // KEYSIZE is 32 bytes
	BYTE pIv[16];                                // IVSIZE is 16 bytes


	srand(time(NULL));                              // the seed to generate the key
	GenerateRandomBytes(pKey, KEYSIZE);             // generating the key bytes

	srand(time(NULL) ^ pKey[0]);                    // The seed to generate the IV. Use the first byte of the key to add more randomness.
	GenerateRandomBytes(pIv, IVSIZE);               // Generating the IV

	// Prints both key and IV to the console
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// Initializing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);


	// Initializing variables that will hold the new buffer base address in the case where padding is required and its size
	PBYTE	PaddedBuffer = NULL;
	SIZE_T	PAddedSize = NULL;

	// Padding the buffer, if required
	if (sizeof(Data) % 16 != 0) {
		PaddBuffer(Data, sizeof(Data), &PaddedBuffer, &PAddedSize);
		// Encrypting the padded buffer instead
		AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PAddedSize);
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", PaddedBuffer, PAddedSize);
	}
	// No padding is required, encrypt 'Data' directly
	else {
		AES_CBC_encrypt_buffer(&ctx, Data, sizeof(Data));
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", Data, sizeof(Data));
	}
	// Freeing PaddedBuffer, if necessary
	if (PaddedBuffer != NULL) {
		HeapFree(GetProcessHeap(), 0, PaddedBuffer);
	}
	system("PAUSE");
	return 0;
}

