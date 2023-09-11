#include <Windows.h>

BOOL __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpvReserved) {

    switch (dwReason) {

    case DLL_PROCESS_ATTACH:
        MessageBoxW(NULL, L"WHO GOES THERE", L"KAW KAW KAW", MB_ICONEXCLAMATION);
        break;
    }

    return TRUE;

}
