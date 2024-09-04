#include <iostream>
#include <Windows.h>
int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        printf("Usage: HookInjector.exe <ProcessId> <Dll path>\n");
        return -1;
    }

    ULONG ProcessId = atoi(argv[1]);
    const char* DllPath = argv[2];
    printf("Injecting hook installer dll to process with id: %u\n ", ProcessId);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    if (!hProcess)
    {
        printf("Failed to open process (PID: %u)\n", ProcessId);
        return -1;
    }

    printf("Allocating memory for the dll path\n");
    // Allocate memory in the remote process
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    
    if (pDllPath == NULL)
    {
        CloseHandle(hProcess);
        printf("Failed to allocate memory for the dll path\n");
        return -1;
    }

    printf("Writing the dll path to the target process\n");
    // Write the DLL path to the allocated memory
    WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath) + 1, NULL);

    printf("Creating remote thread to load the dll in the target process\n");
    // Create a remote thread that calls LoadLibrary
    HANDLE hLoadThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryA"), pDllPath, 0, NULL);
    WaitForSingleObject(hLoadThread, INFINITE);

    return 0;
}
