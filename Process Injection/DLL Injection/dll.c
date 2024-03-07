#include <windows.h>

BOOL __stdcall DllMain(HINSTANCE ModuleHandle, DWORD Reason, LPVOID Reserved) { 

    switch (Reason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxW(NULL, L"WHO GOES THERE", L"KAW KAW KAW", MB_ICONEXCLAMATION);
            break;
    }

    return TRUE;

}
