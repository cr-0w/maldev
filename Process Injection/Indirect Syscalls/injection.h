#pragma once
#include <stdio.h>
#include <windows.h>

//---------------------------------------------------------------------------------

typedef unsigned __int64 QWORD; 
#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define OKAY(MSG, ...) printf("[+] " MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[i] " MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) printf("[-] " MSG "\n", ##__VA_ARGS__)

//---------------------------------------------------------------------------------

#pragma region INJECTION GLOBALS
DWORD g_NtOpenProcessSSN;
DWORD g_NtAllocateVirtualMemorySSN;
DWORD g_NtWriteVirtualMemorySSN;
DWORD g_NtCreateThreadExSSN;
DWORD g_NtWaitForSingleObjectSSN;
DWORD g_NtCloseSSN;

QWORD g_NtOpenProcessSyscall;
QWORD g_NtAllocateVirtualMemorySyscall;
QWORD g_NtWriteVirtualMemorySyscall;
QWORD g_NtCreateThreadExSyscall;
QWORD g_NtWaitForSingleObjectSyscall;
QWORD g_NtCloseSyscall;
#pragma endregion

//---------------------------------------------------------------------------------

#pragma region STRUCTURES
typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
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

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
#pragma endregion

//---------------------------------------------------------------------------------

#pragma region FUNCTION PROTOTYPES
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
#pragma endregion 

//---------------------------------------------------------------------------------

#pragma region FUNCTIONS
/*!
 * @brief Retrive the syscall number for a specific NTAPI.
 *   This can be made to be much better considering you don't need to find syscall
 *   addresses for all the functions you need to use.
 * @param NTDLLHandle The handle to ntdll.
 * @param NtFunctionName The name of the function you want to use.
 * @param NtFunctionSSN The function's SSN.
 * @param NtFunctionSyscallAddress The function's syscall address.
 * @return Void.
 */
VOID IndirectPrelude(
        _In_ HMODULE NTDLLHandle,
        _In_ LPCSTR NtFunctionName,
        _Out_ PDWORD NtFunctionSSN,
        _Out_ PUINT_PTR NtFunctionSyscallAddress
        );

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
 * @brief Injects a target process with indirect syscalls.
 * @param PID The pid of the target process.
 * @param Payload The shellcode byte stream you wish to inject.
 * @param PayloadSize The size of the payload.
 * @return Bool. True if successful, false if not.
 */
BOOL IndirectSyscallsInjection(
        _In_ DWORD PID,
        _In_ CONST PBYTE Payload,
        _In_ SIZE_T PayloadSize
        );
#pragma endregion

//---------------------------------------------------------------------------------
