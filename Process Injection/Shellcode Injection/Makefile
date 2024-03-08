CC := x86_64-w64-mingw32-gcc 
CFLAGS := -O2 -m64 -Wall -Wpedantic

main: main.c
	@echo [*] compiling the DLL injector...
	$(CC) $(CFLAGS) -o shellcode_injector.exe main.c injection.c
	@echo [+] finished! enjoy, nerd.

.PHONY: clean
clean:
	@echo [*] deleting shellcode_injector.exe...
	del shellcode_injector.exe 
