#pragma once
#include <windows.h>
#include <stdio.h>

//-------------------------------------------------------------------------------------------

#define MAX_PATH 260
#define OKAY(MSG, ...) printf("[+] " MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[i] " MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) printf("[-] " MSG "\n", ##__VA_ARGS__)

//-------------------------------------------------------------------------------------------

/*
 * @brief prints out a functions error code with the functions name for easier debugging.
 * @param function_name name of the function.
 * @param error_code the system error code returned by GetLastError();
 * @return void.
 */
VOID PrettyFormat(
        _In_ LPCSTR FunctionName,
        _In_ CONST DWORD Error
        );

/* 
 * @brief injects a target process with a specified dynamic link library (DLL).
 * @param ProcessId The pid of the target process.
 * @param DLLPath The path of the specified DLL.
 * @param dll_path_size the size of the dll_path parameter.
 * @return bool. true if successful, false if not.
 */
BOOL DLLInjection(
        _In_ DWORD ProcessId,
        _In_ LPCWSTR DLLPath,
        _In_ SIZE_T DLLSize 
        );

//-------------------------------------------------------------------------------------------

