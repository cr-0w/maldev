#include "injection.h"

VOID PrettyFormat(
        _In_ LPCSTR FunctionName,
        _In_ CONST DWORD Error
) {

    if (NULL == FunctionName || 0 == Error) {
        WARN("either you didn't supply a function name"
             "or the function actually returned successfully");
    }

    WARN("[%s] failed, error: 0x%lx", FunctionName, Error);
    return;

}

BOOL DLLInjection(
        _In_ CONST DWORD PID,
        _In_ LPCWSTR DLLPath,
        _In_ CONST SIZE_T PathSize
) { 

    BOOL    STATE         = TRUE;
    PVOID   rBuffer       = NULL;
    PVOID   p_LoadLibrary = NULL;
    HANDLE  hThread       = NULL;
    HANDLE  hProcess      = NULL;
    HMODULE hKernel32     = NULL;
    DWORD   TID           = 0;
    SIZE_T  BytesWritten  = 0;

    if (NULL == DLLPath || 0 == PathSize) {
        WARN("target DLL not set. exiting...");
        return FALSE;
    }

    INFO("trying to inject %S to the remote process...", DLLPath);
    INFO("trying to get a handle on the process (%ld)...", PID);
    hProcess = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            FALSE,
            PID
    );
    if (NULL == hProcess) {
        PrettyFormat("OpenProcess", GetLastError());
        return EXIT_FAILURE;
    }
    OKAY("[0x%p] got a handle on the process!", hProcess);

    INFO("getting a handle to Kernel32...");
    hKernel32 = GetModuleHandleW(L"Kernel32.dll");
    if (NULL == hKernel32) {
        PrettyFormat("GetModuleHandleW", GetLastError());
        STATE = FALSE; goto CLEAN_UP;
    }
    OKAY("[0x%p] got a handle to Kernel32!", hKernel32);

    INFO("getting the address of LoadLibraryW...");
    p_LoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
    if (NULL == p_LoadLibrary) {
        PrettyFormat("GetProcAddress", GetLastError());
        STATE = FALSE; goto CLEAN_UP;
    }
    OKAY("[0x%p] obtained the address of LoadLibraryW!", p_LoadLibrary);

    rBuffer = VirtualAllocEx(
            hProcess,
            NULL,
            PathSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
    );
    if (NULL == rBuffer) {
        PrettyFormat("VirtualAllocEx", GetLastError());
        STATE = FALSE; goto CLEAN_UP;
    }
    OKAY("[0x%p] [RW-] allocated %zu-byte buffer to the target process", rBuffer, PathSize);

    if (!WriteProcessMemory(
                hProcess,
                rBuffer,
                DLLPath,
                PathSize,
                &BytesWritten 
    )){
        PrettyFormat("WriteProcessMemory", GetLastError());
        STATE = FALSE; goto CLEAN_UP;
    }
    OKAY("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer", rBuffer, BytesWritten);

    hThread = CreateRemoteThread(
            hProcess,
            NULL,
            0,
            p_LoadLibrary,
            rBuffer,
            0,
            &TID 
    );
    if (NULL == hThread) {
        PrettyFormat("CreateRemoteThread", GetLastError());
        STATE = FALSE; goto CLEAN_UP;
    }
    OKAY("[0x%p] successfully created a thread (%ld)!", hThread, TID);
    INFO("[0x%p] waiting for the thread to finish execution...", hThread);
    WaitForSingleObject(hThread, INFINITE);
    OKAY("[0x%p] thread finished execution, beginning cleanup...", hThread);

CLEAN_UP:

    if (hThread) {
        CloseHandle(hThread);
        INFO("[0x%p] closed handle on thread", hThread);
    }
    if (hProcess) {
        CloseHandle(hProcess);
        INFO("[0x%p] closed handle on process", hProcess);
    }
    INFO("finished with cleanup, exiting...");

    return STATE;

}
