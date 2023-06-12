#include <Windows.h>
#include <stdio.h>
#include "resource.h"

int main() {
	HRSRC	hRsrc = NULL;
	HGLOBAL hGlobal = NULL;
	PVOID	pPayloadAddress = NULL;
	SIZE_T	sPayloadSize = NULL;

	//Gets location to data stored in .rsrc by ID (IDR_RCDATA1) 
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {
		printf("[!] FindResourceW Failed With Error : %d \n", GetLastError());
		return -1;
	}

	//Gets Handle to specified resource data 
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		printf("[!] LoadResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	//Gets address of payload in .rsrc section
	pPayloadAddress = LockResource(hGlobal);
	if (pPayloadAddress == NULL) {
		printf("[!] LockResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	//Gets size of payload in .rsrc section
	sPayloadSize = SizeofResource(NULL, hRsrc);
	if (sPayloadSize == NULL) {
		printf("[!] SizeofResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	printf("[i] pPayloadAddress var : 0x%p \n", pPayloadAddress);
	printf("[i] sPayloadSize var : %ld \n", sPayloadSize);
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	//Create new buffer for payload so it is able to be changed
	//and executed. This is because .rsrc is read-only.

	PVOID pTmpBuffer = HeapAlloc(GetProcessHeap(), 0, sPayloadSize);
	if (pTmpBuffer != NULL) {
		memcpy(pTmpBuffer, pPayloadAddress, sPayloadSize);
	}

	printf("[i] pTmpBuffer var : 0x%p \n", pTmpBuffer);

	return 0;
}