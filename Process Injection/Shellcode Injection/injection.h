#pragma once
#include <windows.h>
#include <stdio.h>

#define OKAY(MSG, ...) printf("[+] " MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[i] " MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) printf("[-] " MSG "\n", ##__VA_ARGS__)
#define PROG(MSG, ...) printf("\r[*] " MSG,    ##__VA_ARGS__) /* solely for iterations */

/*!
 * @brief 
 *  Prints out a functions error code with the functions name for easier debugging.
 *
 * @param FunctionName 
 *  Name of the function.
 *
 * @param Error 
 *  The system error code returned by GetLastError();
 *  GetLastError() just reads from the _TEB at the LastError member/offset (_TEB->LastError), 
 *  so any function/routine that does this can be used in place of GetLastError().
 *
 * @return Void.
 */
VOID PrettyFormat(
        _In_ LPCSTR FunctionName,
        _In_ CONST DWORD Error
);

/*!
 * @brief 
 *  Injects a target process using classic shellcode injection with Win32 API.
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
