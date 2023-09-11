#pragma once
#pragma comment (lib, "ntdll")

#include <Windows.h>
#include <stdio.h>

/*------[SETUP MACROS]------*/
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)

/*------[STRUCTURES]------*/
typedef struct _PS_ATTRIBUTE {
    ULONGLONG Attribute;				
    SIZE_T Size;						
    union {
        ULONG_PTR Value;				
        PVOID ValuePtr;					
    };
    PSIZE_T ReturnLength;				
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;					
    PS_ATTRIBUTE Attributes[2];			
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;                                                           //0x0
    VOID* RootDirectory;                                                    //0x8
    struct _UNICODE_STRING* ObjectName;                                     //0x10
    ULONG Attributes;                                                       //0x18
    VOID* SecurityDescriptor;                                               //0x20
    VOID* SecurityQualityOfService;                                         //0x28
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

/*------[FUNCTION PROTOTYPE]------*/
typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
    _Out_    PHANDLE            ThreadHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_     HANDLE             ProcessHandle,
    _In_     PVOID              StartRoutine,
    _In_opt_ PVOID              Argument,
    _In_     ULONG              CreateFlags,
    _In_     SIZE_T             ZeroBits,
    _In_     SIZE_T             StackSize,
    _In_     SIZE_T             MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList);