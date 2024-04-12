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
 *  Gets the context of a thread that's in a suspended state, updates its instruction 
 *  pointer to point to a payload buffer.
 *  
 * @param ThreadHandle.
 *  A valid handle to a thread that's in a suspended state.
 *
 * @param Buffer.
 *  A pointer to the allocated buffer where your payload will be going into.
 *
 * @param PayloadSize
 *  The size of the payload.
 *
 * @return Bool.
 *  True if successful, false if not.
 */
BOOL LocalThreadHijack(
        _In_ HANDLE ThreadHandle,
        _In_ PVOID Buffer,
        _In_ PBYTE Payload,
        _In_ SIZE_T PayloadSize 
);

/*!
 * @brief
 *  A dummy function to motivate the creation of a suspended thread.
 *
 * @param Void.
 *
 * @note 
 *  This function can literally be whatever you want. Typically, you might like to
 *  use benign functions that don't do anything or are harmless.
 *
 * @return Void.
 */
VOID DummyFunction(VOID);

/*!
 * @brief
 * Prints the technique banner.
 * 
 * @param Void.
 * 
 * @return Void.
 */
VOID PrintBanner(VOID);
