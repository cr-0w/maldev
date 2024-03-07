CC := gcc
CFLAGS := -O2 -m64 

main: main.c
	@echo [*] compiling the DLL injector...
	$(CC) $(CFLAGS) -o dll_injection.exe main.c injection.c
	@echo [+] finished! enjoy, nerd.

.PHONY: clean
clean:
	@echo [*] deleting dll_injection.exe...
	del dll_injection.exe 
