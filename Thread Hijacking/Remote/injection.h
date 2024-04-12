#pragma once
#include <stdio.h>
#include <windows.h>

#define OKAY(MSG, ...) printf("[+] "               MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "               MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] "      MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(FUNCTION_NAME)                                        \
    do {                                                                  \
        fprintf(stderr,                                                   \
                "[!] [" FUNCTION_NAME "] [%s:%d] failed, error: 0x%lx\n", \
                __FILE__, __LINE__, GetLastError());                      \
    } while (0)


/*!
 * @brief
 *  Creates a process in a suspended state.
 * 
 * @param ProcessName
 *  The name of the process you wish to start. This should be something present in %WINDIR%\System32\*.
 * 
 * @param ProcessId
 *  The PID of the suspended process.
 *
 * @param ProcessHandle
 *  A valid handle to the suspended process.
 *
 * @param ThreadHandle
 *  A valid thread handle for the suspended process.
 *
 * @return Bool
 *  True if successful, false if not.
 *
 */
BOOL CreateSuspendedProcess(
    _In_  LPCSTR ProcessName,
	_Out_ PDWORD ProcessId,
	_Out_ PHANDLE ProcessHandle,
	_Out_ PHANDLE ThreadHandle
);

/*!
 * @brief
 *  Gets the context of a thread that's in a suspended state, updates its instruction 
 *  pointer to point to a payload buffer.
 *  
 * @param ThreadHandle
 *  A valid handle to a thread that's in a suspended state.
 *
 * @param ProcessHandle
 *
 * @param Buffer
 *  A pointer to the allocated buffer where your payload will be going into.
 *
 * @param PayloadSize
 *  The size of the payload
 *
 * @return Bool
 *  True if successful, false if not.
 */
BOOL RemoteThreadHijack(
        _In_ HANDLE ThreadHandle,
        _In_ HANDLE ProcessHandle,
        _In_ PVOID Buffer,
        _In_ PBYTE Payload,
        _In_ SIZE_T PayloadSize 
);

/*!
 * @brief
 * Prints the technique banner.
 * 
 * @param Void.
 * 
 * @return Void.
 */
VOID PrintBanner(VOID);
