#include<stdio.h>
#include<Windows.h>

typedef void (WINAPI* HelloWorldFunctionPointer)(char[]);

int main() {
	HMODULE hModule = LoadLibraryA("C:\\Users\\jackm\\Desktop\\malDev\\DLL_Modules\\x64\\Debug\\DLL_Modules.dll");
	PVOID pHelloWorld = GetProcAddress(hModule, "HelloWorld");

	HelloWorldFunctionPointer HelloWorld = (HelloWorldFunctionPointer)pHelloWorld;
	HelloWorld("This is Jack");

	return 0;
}