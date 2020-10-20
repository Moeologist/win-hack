#include <Windows.h>

WNDPROC originalWndProc = NULL;

LRESULT __declspec(dllexport) CALLBACK
    WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_NCACTIVATE)
        return 0;
    if (message == WM_ACTIVATEAPP && wParam == FALSE)
        return 0;
    return CallWindowProc(originalWndProc, hWnd, message, wParam, lParam);
}

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    DWORD pid = GetCurrentProcessId();
    DWORD hWnd_pid = 0;
    GetWindowThreadProcessId(hWnd, &hWnd_pid);
    if (pid == hWnd_pid) {
        *(HWND *)lParam = hWnd;
        return FALSE;
    }
    return TRUE;
}

HWND GetCurrentHWND() {
    HWND hWnd = 0;
    EnumWindows(EnumWindowsProc, (LPARAM)&hWnd);
    return hWnd;
}

void Hook() {
    HWND hWindow = NULL;
    while (hWindow == NULL) {
        hWindow = GetCurrentHWND();
        // See also FindWindow
        Sleep(100);
    }
    LONG_PTR lp = SetWindowLongPtr(hWindow, GWLP_WNDPROC, (LONG_PTR)WndProc);
    // Changes WNDPROC of the specified window

    originalWndProc = (WNDPROC)lp;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            // This can reduce the size of the working set for some applications.

            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Hook, hModule,
                         NULL, NULL);
            // Run Hook in new thread
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}