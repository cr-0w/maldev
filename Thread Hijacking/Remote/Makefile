CC := x86_64-w64-mingw32-gcc
CFLAGS := -O2 -m64 -Wall -Wpedantic

main: main.c 
	@echo [*] compiling the thread hijacker...
	$(CC) $(CFLAGS) -o remote_thread_hijacker.exe main.c injection.c
	@echo [!] do not worry about all the errors, that is just for the nerds, i promise.
	@echo [+] finished! enjoy, nerd.

.PHONY: clean
clean:
	@echo [*] deleting remote_thread_hijacker.exe...
	del remote_thread_hijacker.exe
