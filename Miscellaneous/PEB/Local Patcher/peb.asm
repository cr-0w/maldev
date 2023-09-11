.code

GETPEB proc
		mov rax, gs:[60h]            ; PEB
		ret
GETPEB endp

PEBPATCHER proc
		xor eax, eax
		call GETPEB
		movzx eax, byte ptr [rax+2h] ; PEB->BeingDebugged
		test eax, eax
		jnz PATCHPEB
		ret

PATCHPEB:
		xor eax, eax
		call GETPEB
		mov byte ptr [rax+2h], 0     ; PATCHED
		ret

PEBPATCHER endp
end
