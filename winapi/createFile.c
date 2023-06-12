#include<stdio.h>
#include<windows.h>

int main() {
	LPWSTR fileName = L"MalDevWinAPI.txt";
	HANDLE fileHandler = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (fileHandler == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW Api Function Failed With Error : %d\n", GetLastError());
		return -1;
	}

	LPSTR username[1024];
	DWORD username_len = 1024;
	GetUserNameA(username, &username_len);

	printf("Username: %s\n", username);
}