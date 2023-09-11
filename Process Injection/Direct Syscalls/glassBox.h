#pragma once

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

/*-------------[MACROS]-------------*/
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__);
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__);
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__);

/*-------------[STRUCTURES]-------------*/
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

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

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

/*-------------[FUNCTIONS]-------------*/
extern NTSTATUS NtOpenProcess(
	OUT    PHANDLE            ProcessHandle,
	IN     ACCESS_MASK        DesiredAccess,
	IN     POBJECT_ATTRIBUTES ObjectAttributes,
	IN     PCLIENT_ID         ClientId OPTIONAL);

extern NTSTATUS NtAllocateVirtualMemory(
	IN     HANDLE             ProcessHandle,
	IN OUT PVOID*             BaseAddress,
	IN     ULONG              ZeroBits,
	IN OUT PSIZE_T            RegionSize,
	IN     ULONG              AllocationType,
	IN     ULONG              Protect);

extern NTSTATUS NtWriteVirtualMemory(
	IN     HANDLE             ProcessHandle,
	IN     PVOID              BaseAddress,
	IN     PVOID              Buffer,
	IN     SIZE_T             NumberOfBytesToWrite,
	OUT    PSIZE_T            NumberOfBytesWritten OPTIONAL);

extern NTSTATUS NtCreateThreadEx(
	OUT    PHANDLE            ThreadHandle,
	IN     ACCESS_MASK        DesiredAccess,
	IN     POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN     HANDLE             ProcessHandle,
	IN     PVOID              StartRoutine,
	IN     PVOID              Argument OPTIONAL,
	IN     ULONG              CreateFlags,
	IN     SIZE_T             ZeroBits,
	IN     SIZE_T             StackSize,
	IN     SIZE_T             MaximumStackSize,
	IN     PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

extern NTSTATUS NtWaitForSingleObject(
	IN     HANDLE             Handle,
	IN     BOOLEAN            Alertable,
	IN     PLARGE_INTEGER     Timeout);

extern NTSTATUS NtClose(
	IN     HANDLE             Handle);
