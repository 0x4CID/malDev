#include<stdio.h>
#include<Windows.h>
#include<Memoryapi.h>


int main() {
	PVOID mallocMem = malloc(100);
	printf("Malloc Memory: 0x%p\n", mallocMem);

	PVOID heapAllocMem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100);
	printf("HeapAlloc Memory: 0x%p\n", heapAllocMem);

	PVOID localAllocMem = LocalAlloc(0, 100);
	printf("LocalAlloc Memory: 0x%p\n", localAllocMem);

	// Writing to memory
	char* cString = "This has been written to";

	memcpy(heapAllocMem, cString, strlen(cString));

	printf("Address: 0x%p\nContents: %s\n", heapAllocMem, heapAllocMem);


	SecureZeroMemory(heapAllocMem, 100);

	// Free the memory assigned

	free(mallocMem);
	HeapFree(GetProcessHeap(), 0, heapAllocMem);
	LocalFree(localAllocMem);

	// Allocating memory using VirtualAlloc

	PVOID VirtualAllocMem = VirtualAlloc(NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RtlFillMemory(VirtualAllocMem, 100, 0x4141);
	printf("VirtualAllocMem: 0x%p\n", VirtualAllocMem);




	return 0;

}