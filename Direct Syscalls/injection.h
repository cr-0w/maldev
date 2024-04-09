#pragma once
#include <stdio.h>
#include <windows.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] "               MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "               MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] "      MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(FUNCTION_NAME, NTSTATUS_ERROR)                        \
    do {                                                                  \
        fprintf(stderr,                                                   \
                "[!] [" FUNCTION_NAME "] [%s:%d] failed, error: 0x%lx\n", \
                __FILE__, __LINE__, NTSTATUS_ERROR);                      \
    } while (0)

DWORD g_NtOpenProcessSSN;
DWORD g_NtAllocateVirtualMemorySSN;
DWORD g_NtWriteVirtualMemorySSN;
DWORD g_NtProtectVirtualMemorySSN;
DWORD g_NtCreateThreadExSSN;
DWORD g_NtWaitForSingleObjectSSN;
DWORD g_NtFreeVirtualMemorySSN;
DWORD g_NtCloseSSN;

typedef struct _PS_ATTRIBUTE {
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

extern NTSTATUS NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
);

extern NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

extern NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

extern NTSTATUS NtProtectVirtualMemory(
    _In_      HANDLE ProcessHandle,
    _Inout_   PVOID* BaseAddress,
    _Inout_   PSIZE_T RegionSize,
    _In_      ULONG NewProtect,
    _Out_     PULONG OldProtect
);

extern NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
);

extern NTSTATUS NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

extern NTSTATUS NtFreeVirtualMemory(
    _In_      HANDLE ProcessHandle,
    _Inout_   PVOID* BaseAddress,
    _Inout_   PSIZE_T RegionSize,
    _In_      ULONG FreeType
);

extern NTSTATUS NtClose(
    IN HANDLE Handle
);

/*!
 * @brief
 *  Retreives the syscall number for a specific NTAPI function.
 *
 *  This function will get the address of a specified NTAPI function
 *  using GetProcAddress(). After successfully doing that, 
 *  the function will then scrape the specified NTAPI function's SSN 
 *  by reading the offset of the base address + 0x04.
 *
 *  NtFunction+0x0:  4c 8b d1        mov r10, rcx
 *  NtFunction+0x3:  b8 ?? 00 00 00  mov eax, [??]
 *  ...              ...             ...       |
 *  NtFunction+0x12: 0f 05           syscall   |
 *  NtFunction+0x14: c3              ret       |
 *                                             |
 *  .------------------------------------------'
 *  |
 *  '---------------------------> SSN : (+0x04)
 *
 * @param NtdllHandle
 *  A valid handle to NTDLL.dll.
 *
 * @param NtFunctionName
 *  The name of the NTAPI function you want to use.
 *
 * @param NtFunctionSSN
 *  The extracted SSN of the NTAPI function.
 * 
 * @note
 *  This function wasn't built with OPSEC in mind.
 *  It uses GetProcAddress() to get the base address of the specified
 *  NTAPI function which is already bad OPSEC practice. A program
 *  with GetProcAddress() in its IAT will be under more scrutiny than
 *  a program without it (due to GetProcAddress() being
 *  commonly-(u|abu)sed in offensive development.
 * 
 * @note
 *  This function does not account for the altered offsets in the case 
 *  of API hooks placed by security solutions. This function will fall
 *  apart like wet paper if a specified NTAPI function has been hooked
 *  because of the offsets being all mangled and borked. There are 
 *  methods to circumnavigate these pesky API hooks, but that's left
 *  as an exercise for you to go do.
 * 
 * @return Void.
 */
VOID GetSyscallNumber(
    _In_  HMODULE NtdllHandle,
    _In_  LPCSTR NtFunctionName,
    _Out_ PDWORD NtFunctionSSN
);

/*!
 * @brief
 *  Injects a target process with direct syscalls.
 *
 * @param PID
 *  The pid of the target process.
 *
 * @param Payload
 *  The shellcode byte stream you wish to inject.
 *
 * @param PayloadSize
 *  The size of the payload.
 *
 * @return Bool.
 *  True if successful, false if not.
 */
BOOL DirectSyscallsInjection(
    _In_ CONST DWORD PID,
    _In_ CONST PBYTE Payload,
    _In_ CONST SIZE_T PayloadSize
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
