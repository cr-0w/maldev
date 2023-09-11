.data

EXTERN NtCloseSSN:DWORD                
EXTERN NtOpenProcessSSN:DWORD          
EXTERN NtCreateThreadExSSN:DWORD       
EXTERN NtWriteVirtualMemorySSN:DWORD   
EXTERN NtWaitForSingleObjectSSN:DWORD  
EXTERN NtAllocateVirtualMemorySSN:DWORD

.code

NtOpenProcess proc
		mov r10, rcx
		mov eax, NtOpenProcessSSN       ; SSN will be retrieved by reading &function+0x4
		syscall                         ; can replace with int 2eh as well
		ret                             
NtOpenProcess endp

NtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, NtAllocateVirtualMemorySSN      
		syscall                        
		ret                             
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
		mov r10, rcx
		mov eax, NtWriteVirtualMemorySSN      
		syscall                        
		ret                             
NtWriteVirtualMemory endp

NtCreateThreadEx proc
		mov r10, rcx
		mov eax, NtCreateThreadExSSN      
		syscall                        
		ret                             
NtCreateThreadEx endp

NtWaitForSingleObject proc
		mov r10, rcx
		mov eax, NtWaitForSingleObjectSSN      
		syscall                        
		ret                             
NtWaitForSingleObject endp

NtClose proc
		mov r10, rcx
		mov eax, NtCloseSSN      
		syscall                        
		ret                             
NtClose endp
end
