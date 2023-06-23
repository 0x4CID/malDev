#include <stdio.h>
#include <Windows.h>

typedef void (WINAPI* ExecFunctionPointer)();

int main(int argc, char* argv[]) {


	HMODULE hModule = LoadLibraryA("C:\\Users\\jackm\\Desktop\\malDev\\ExecDLLShellcode\\ExecDLLShellcode\\x64\\Debug\\ShellcodeDLL.dll");


	PVOID pRun = GetProcAddress(hModule, "execPayload");
	ExecFunctionPointer runDll = (ExecFunctionPointer)pRun;
	runDll();

	//getchar();
	return 0;

}