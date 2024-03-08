#pragma once
#include <windows.h>
#include <stdio.h>

#define MAX_PATH 260
#define DLL L"dll\\crow.dll"
#define OKAY(MSG, ...) printf("[+] " MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] " MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) printf("[-] " MSG "\n", ##__VA_ARGS__)

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
 *  Injects a target process with a specified dynamic link library (DLL).
 *
 * @param PID 
 *  The pid of the target process.
 *
 * @param DLLPath 
 *  The path of the specified DLL.
 *
 * @param PathSize 
 *  The size of the DLLPath parameter.
 *
 * @return Bool
 * True if successful, false if not.
 */
BOOL DLLInjection(
        _In_ CONST DWORD PID,
        _In_ LPCWSTR DLLPath,
        _In_ CONST SIZE_T PathSize 
);
