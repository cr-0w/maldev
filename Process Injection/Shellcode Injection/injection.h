#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

//-------------------------------------------------------------------------------------------

#define OKAY(MSG, ...) printf("[+] " MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[i] " MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) printf("[-] " MSG "\n", ##__VA_ARGS__)
#define PROGRESS(MSG, ...) printf("\r[*] " MSG, ##__VA_ARGS__) /* solely for iterations */

//-------------------------------------------------------------------------------------------

/*
 * @brief Formats an error.
 * @param FunctionName the name of the function that's failed.
 * @param ErrorStatus the status returned by the function.
 * @return Void.
 */
VOID PrettyFormat(
        _In_ LPCSTR FunctionName,
        _In_ CONST DWORD ErrorStatus
        );

/*
 * @brief Injects a target process using classic shellcode injection with Win32 API.
 * @param ProcessId The PID of the target process.
 * @param Payload The shellcode you wish to inject.
 * @param PayloadSize The Size of the shellcode.
 * @return Bool. True if successful, false if not.
 */
BOOL ShellcodeInjection(
        _In_ DWORD ProcessId,
        _In_ CONST PBYTE Payload,
        _In_ SIZE_T PayloadSize
        );

//-------------------------------------------------------------------------------------------

