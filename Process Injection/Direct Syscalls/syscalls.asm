.data 
extern g_NtOpenProcessSSN:DWORD
extern g_NtAllocateVirtualMemorySSN:DWORD
extern g_NtWriteVirtualMemorySSN:DWORD
extern g_NtCreateThreadExSSN:DWORD
extern g_NtWaitForSingleObjectSSN:DWORD
extern g_NtCloseSSN:DWORD

.code
NtOpenProcess proc 
		mov r10, rcx
		mov eax, g_NtOpenProcessSSN       
		syscall                         
		ret                             
NtOpenProcess endp

NtAllocateVirtualMemory proc    
		mov r10, rcx
		mov eax, g_NtAllocateVirtualMemorySSN      
		syscall                        
		ret                             
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc 
		mov r10, rcx
		mov eax, g_NtWriteVirtualMemorySSN      
		syscall                        
		ret                             
NtWriteVirtualMemory endp 

NtCreateThreadEx proc 
		mov r10, rcx
		mov eax, g_NtCreateThreadExSSN      
		syscall                        
		ret                             
NtCreateThreadEx endp 

NtWaitForSingleObject proc 
		mov r10, rcx
		mov eax, g_NtWaitForSingleObjectSSN      
		syscall                        
		ret                             
NtWaitForSingleObject endp 

NtClose proc 
		mov r10, rcx
		mov eax, g_NtCloseSSN      
		syscall                        
		ret                             
NtClose endp 
end
