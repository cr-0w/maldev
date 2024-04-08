#pragma once
#include <windows.h>
#include <stdio.h>

#define OKAY(MSG, ...) printf("[+] "          MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(FUNCTION_NAME)                                   \
    do {                                                             \
        fprintf(stderr,                                              \
                "[!] [" FUNCTION_NAME "] failed, error: 0x%lx\n"     \
                "[*] %s:%d\n", GetLastError(), __FILE__, __LINE__);  \
    } while (0)

/*!
 * @brief
 *  Injects a target process using the classic shellcode injection method via the WinAPI.
 *
 *  The program starts by getting a valid handle on the target process, allocating a memory
 *  page/buffer within it, writing our payload into that allocated memory, optionally: changing
 *  memory permissions for the buffer to have executable rights on it, and finally, creating
 *  a thread that will run our payload.
 *
 * @param PID
 *  The PID of the target process.
 *
 * @param Payload
 *  The shellcode you wish to inject.
 *
 * @param PayloadSize
 *  The Size of the shellcode.
 *
 * @return Bool
 *  True if successful, false if not.
 */
BOOL ShellcodeInjection(
    _In_ CONST DWORD PID,
    _In_ CONST PBYTE Payload,
    _In_ CONST SIZE_T PayloadSize
);
