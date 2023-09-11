.code

getTEB proc
		mov rax, qword ptr gs:[30h]  ; self-referencing TEB 
		ret
getTEB endp

CustomError proc
		xor eax, eax
		call getTEB
		mov eax, dword ptr [rax+68h] ; LastErrorValue
		ret
CustomError endp
end