#include "injection.h"

BOOL DLLInjection(
    _In_ LPCWSTR DllPath,
    _In_ CONST DWORD PID,
    _In_ CONST SIZE_T PathSize
) {

    BOOL    State          = TRUE;
    DWORD   TID            = 0;
    SIZE_T  BytesWritten   = 0;
    PVOID   Buffer         = NULL;
    PVOID   p_LoadLibrary  = NULL;
    HANDLE  ThreadHandle   = NULL;
    HANDLE  ProcessHandle  = NULL;
    HMODULE Kernel32Handle = NULL;

    ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (NULL == ProcessHandle) {
        PRINT_ERROR("OpenProcess");
        return FALSE; /* no point in continuing if we can't even get a handle on the process */
    }
    OKAY("[0x%p] got a handle on the process (%ld)!", ProcessHandle, PID);

    Kernel32Handle = GetModuleHandleW(L"Kernel32.dll");
    if (NULL == Kernel32Handle) {
        PRINT_ERROR("GetModuleHandleW");
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] got a handle to Kernel32!", Kernel32Handle);

    p_LoadLibrary = GetProcAddress(Kernel32Handle, "LoadLibraryW");
    if (NULL == p_LoadLibrary) {
        PRINT_ERROR("GetProcAddress");
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] obtained the address of LoadLibraryW!", p_LoadLibrary);

    Buffer = VirtualAllocEx(ProcessHandle, NULL, PathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NULL == Buffer) {
        PRINT_ERROR("VirtualAllocEx");
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] allocated a buffer with PAGE_READWRITE [RW-] permissions!", Buffer);

    if (!WriteProcessMemory(ProcessHandle, Buffer, DllPath, PathSize, &BytesWritten)) {
        PRINT_ERROR("WriteProcessMemory");
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer", Buffer, BytesWritten);

    ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)p_LoadLibrary, Buffer, 0, &TID);
    if (NULL == ThreadHandle) {
        PRINT_ERROR("CreateRemoteThread");
        State = FALSE; goto CLEANUP;
    }

    OKAY("[0x%p] successfully created a thread (%ld)!", ThreadHandle, TID);
    INFO("[0x%p] waiting for the thread to finish execution...", ThreadHandle);
    WaitForSingleObject(ThreadHandle, INFINITE);
    OKAY("[0x%p] thread finished execution, beginning cleanup...", ThreadHandle);

CLEANUP:

    if (ThreadHandle) {
        CloseHandle(ThreadHandle);
        INFO("[0x%p] closed handle on thread", ThreadHandle);
    }

    if (ProcessHandle) {
        CloseHandle(ProcessHandle);
        INFO("[0x%p] closed handle on process", ProcessHandle);
    }

    if (Buffer) {
        VirtualFree(Buffer, 0, MEM_RELEASE);
        INFO("[0x%p] allocated buffer freed", Buffer);
    }

    return State;

}
