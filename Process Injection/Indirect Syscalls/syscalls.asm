.data

EXTERN NtOpenProcessSSN:DWORD          
EXTERN NtOpenProcessSyscall:QWORD

EXTERN NtAllocateVirtualMemorySSN:DWORD
EXTERN NtAllocateVirtualMemorySyscall:QWORD

EXTERN NtWriteVirtualMemorySSN:DWORD
EXTERN NtWriteVirtualMemorySyscall:QWORD  

EXTERN NtWaitForSingleObjectSSN:DWORD
EXTERN NtWaitForSingleObjectSyscall:QWORD  

EXTERN NtCreateThreadExSSN:DWORD       
EXTERN NtCreateThreadExSyscall:QWORD 

EXTERN NtCloseSSN:DWORD
EXTERN NtCloseSyscall:QWORD

.code

NtOpenProcess proc
		mov r10, rcx
		mov eax, NtOpenProcessSSN       
		jmp qword ptr [NtOpenProcessSyscall]                         
		ret                             
NtOpenProcess endp

NtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, NtAllocateVirtualMemorySSN      
		jmp qword ptr [NtAllocateVirtualMemorySyscall]                        
		ret                             
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
		mov r10, rcx
		mov eax, NtWriteVirtualMemorySSN      
		jmp qword ptr [NtWriteVirtualMemorySyscall]                        
		ret                             
NtWriteVirtualMemory endp

NtCreateThreadEx proc
		mov r10, rcx
		mov eax, NtCreateThreadExSSN      
		jmp qword ptr [NtCreateThreadExSyscall]                        
		ret                             
NtCreateThreadEx endp

NtWaitForSingleObject proc
		mov r10, rcx
		mov eax, NtWaitForSingleObjectSSN      
		jmp qword ptr [NtWaitForSingleObjectSyscall]                        
		ret                             
NtWaitForSingleObject endp

NtClose proc
		mov r10, rcx
		mov eax, NtCloseSSN      
		jmp qword ptr [NtCloseSyscall]                        
		ret                             
NtClose endp
end