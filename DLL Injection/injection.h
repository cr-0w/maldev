#pragma once
#include <windows.h>
#include <stdio.h>

#define DLL L"dll\\crow.dll"
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
 *  Injects a target process with a specified dynamic link library (DLL).
 *
 *  Similar to the standard shellcode injection method, most of the steps
 *  we perform in this method are the same. The only difference is that
 *  we're injecting a library/module/DLL/whatever into a target process. Once a
 *  DLL is loaded in a process, its' DllMain() function is executed automagically.
 *
 *  To do this injection, we get a valid handle on the target process, allocate
 *  some memory into it, write the path to our DLL into that memory region. Then,
 *  before anything else, we need to find the address of LoadLibrary() which takes
 *  in a module to load (or the path to one) as an argument. LoadLibrary() is
 *  exported from Kernel32.dll. So, we first need to get a handle on Kernel32,
 *  afterwhich, we look inside of this module and find the address of LoadLibrary()
 *  with the GetProcAddress() function.
 *
 *  With the address of LoadLibrary() now obtained, we can create a thread with it as
 *  our starting address. Also, we must supply the rBuffer (which holds our DLL path)
 *  as an argument for LoadLibrary(); which we do by setting CreateRemoteThread's
 *  lpParameter to. Effectively, we're doing p_LoadLibrary(rBuffer) which is the same
 *  as LoadLibrary(DllPath);
 *
 * @param DLLPath
 *  The path of the specified DLL.
 *
 * @param PID
 *  The pid of the target process.
 *
 * @param PathSize
 *  The size of the DLLPath parameter.
 *
 * @return Bool
 *  True if successful, false if not.
 */
BOOL DLLInjection(
    _In_ LPCWSTR DLLPath,
    _In_ CONST DWORD PID,
    _In_ CONST SIZE_T PathSize
);
