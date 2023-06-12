#include <windows.h>
#include <sddl.h>
#include <stdio.h>

int main() {
	int pid = 20364;
	HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
	LPVOID info;

	if (procHandle == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW Api Function Failed With Error : %d\n", GetLastError());
		return -1;
	}

    PSECURITY_DESCRIPTOR securityDescriptor;
    DWORD securityDescriptorSize = 0;
    if (!GetKernelObjectSecurity(procHandle, DACL_SECURITY_INFORMATION, NULL, 0, &securityDescriptorSize))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            printf("Failed to get security descriptor size. Error code: %d\n", GetLastError());
            return 1;
        }
    }

    securityDescriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, securityDescriptorSize);
    if (securityDescriptor == NULL)
    {
        printf("Failed to allocate memory for security descriptor. Error code: %d\n", GetLastError());
        return 1;
    }

    if (!GetKernelObjectSecurity(procHandle, DACL_SECURITY_INFORMATION, securityDescriptor, securityDescriptorSize, &securityDescriptorSize))
    {
        printf("Failed to get security descriptor. Error code: %d\n", GetLastError());
        LocalFree(securityDescriptor);
        return 1;
    }

    LPSTR securityDescriptorString;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorA(securityDescriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &securityDescriptorString, NULL))
    {
        printf("Failed to convert security descriptor to string. Error code: %d\n", GetLastError());
        LocalFree(securityDescriptor);
        return 1;
    }

    printf("Security Descriptor: %s\n", securityDescriptorString);

    LocalFree(securityDescriptor);
    LocalFree(securityDescriptorString);
    CloseHandle(procHandle);

    return 0;
}
