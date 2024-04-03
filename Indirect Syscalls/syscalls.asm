.data 
extern g_NtOpenProcessSSN:DWORD
extern g_NtOpenProcessSyscall:QWORD
extern g_NtAllocateVirtualMemorySSN:DWORD
extern g_NtAllocateVirtualMemorySyscall:QWORD
extern g_NtWriteVirtualMemorySSN:DWORD
extern g_NtWriteVirtualMemorySyscall:QWORD
extern g_NtProtectVirtualMemorySSN:DWORD
extern g_NtProtectVirtualMemorySyscall:QWORD
extern g_NtCreateThreadExSSN:DWORD
extern g_NtCreateThreadExSyscall:QWORD
extern g_NtWaitForSingleObjectSSN:DWORD
extern g_NtWaitForSingleObjectSyscall:QWORD
extern g_NtFreeVirtualMemorySSN:DWORD
extern g_NtFreeVirtualMemorySyscall:QWORD
extern g_NtCloseSSN:DWORD
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

NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, g_NtProtectVirtualMemorySSN       
		jmp qword ptr g_NtProtectVirtualMemorySyscall                         
		ret                             
NtProtectVirtualMemory endp

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

NtFreeVirtualMemory proc
		mov r10, rcx
		mov eax, g_NtFreeVirtualMemorySSN      
		jmp qword ptr g_NtFreeVirtualMemorySyscall                        
		ret                             
NtFreeVirtualMemory endp

NtClose proc
		mov r10, rcx
		mov eax, g_NtCloseSSN      
		jmp qword ptr g_NtCloseSyscall                        
		ret                             
NtClose endp
end