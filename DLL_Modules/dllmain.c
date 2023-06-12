// dllmain.cpp : Defines the entry point for the DLL application.

#include "stdio.h"

extern __declspec(dllexport) void HelloWorld(char string[]) {
	FILE* fptr;
	fptr = fopen("..\\testdoc.txt", "a");


	fprintf(fptr, string);


	fclose(fptr);
}



