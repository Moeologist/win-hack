#include <assert.h>
#include <stdio.h>
#include <windows.h>

#ifdef UNICODE
#define LOAD_LIBRARY_STR "LoadLibraryW"
#define PathFileExists PathFileExistsW
#else
#define LOAD_LIBRARY_STR "LoadLibraryA"
#define PathFileExists PathFileExistsA
#endif

// https://en.wikipedia.org/wiki/DLL_injection
DWORD inject_DLL(const char *file_name, int PID) {
    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (h_process == NULL)
        printf("Get process handle failed\n");

    char fullDLLPath[_MAX_PATH];
    DWORD length = GetFullPathName(file_name, _MAX_PATH, fullDLLPath, NULL);
    if (length == 0)
        printf("Get DLL full path failed\n");

    if (GetFileAttributes(fullDLLPath) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributes(fullDLLPath) & FILE_ATTRIBUTE_DIRECTORY)
        printf("DLL file not exists\n");

    LPVOID DLLPath_addr = VirtualAllocEx(
        h_process, NULL, _MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (DLLPath_addr == NULL)
        printf("Allocating memory in the target process failed\n");

    if (WriteProcessMemory(h_process, DLLPath_addr, fullDLLPath, length,
                           NULL) == 0)
        printf("Writing the dll path into remote memory failed\n");

    LPVOID LoadLib_addr =
        GetProcAddress(GetModuleHandle("Kernel32"), LOAD_LIBRARY_STR);
    //getting LoadLibraryA address (same across all processes) to start execution at it

    HANDLE h_rThread = CreateRemoteThread(h_process, NULL, 0,
                                          (LPTHREAD_START_ROUTINE)LoadLib_addr,
                                          DLLPath_addr, 0, 0);
    //starting a remote execution thread at LoadLibraryA and passing the dll path as an argument
    if (h_rThread == NULL)
        printf("Start remote thread failed\n");

    WaitForSingleObject(h_rThread, INFINITE); //waiting for it to be finished

    DWORD exit_code;
    GetExitCodeThread(h_rThread, &exit_code);
    //retrieving the return value, i.e., the module handle returned by LoadLibraryA

    CloseHandle(h_rThread);
    VirtualFreeEx(h_process, DLLPath_addr, 0, MEM_RELEASE);
    CloseHandle(h_process);
    //freeing the injected thread handle,
    //and the memory allocated for the DLL path,
    //and the handle for the target process

    return exit_code;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <PID> <*.dll>", argv[0]);
        return 1;
    }
    int PID = 0;
    sscanf(argv[1], "%d", &PID);
    return (int)inject_DLL(argv[2], PID);
}