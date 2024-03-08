CC := x86_64-w64-mingw32-gcc
CFLAGS := -O2 -m64 -Wall -Wpedantic
DLL_DIR := dll

main: main.c $(DLL_DIR)/crow.dll
	@echo [*] compiling the DLL injector...
	$(CC) $(CFLAGS) -o dll_injector.exe main.c injection.c
	@echo [!] do not worry about all the errors, that is just for the nerds, i promise.
	@echo [+] finished! enjoy, nerd.

$(DLL_DIR)/crow.dll: $(DLL_DIR)/dll.c
	@echo [*] compiling the DLL...
	$(CC) $(CFLAGS) -shared -o $(DLL_DIR)/crow.dll $(DLL_DIR)/dll.c

.PHONY: clean
clean:
	@echo [*] deleting dll_injector.exe...
	del dll_injector.exe
	@echo [*] deleting DLL files...
	del $(DLL_DIR)\crow.dll
