#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)

//----------------[ REMOTE PEB-PATCHER COMING SOON, IDK ]

extern PPEB GETPEB(VOID);
extern void PEBPATCHER(VOID);

int main(int argc, char* argv[]) {

	info("getting the PEB");
	PPEB pPEB = GETPEB();
	okay("\\___[ PEB\n\t\\_0x%p]\n", pPEB);
	info("checking for a debugger presence");
	okay("[PEB->BeingDebugged: 0x%d]", pPEB->BeingDebugged);

	if (pPEB->BeingDebugged) {
		warn("being debugged!");
		info("patching the PEB");
		PEBPATCHER();
		okay("[PEB->BeingDebugged: 0x%d]", pPEB->BeingDebugged);

		if (pPEB->BeingDebugged != 0x0) {
			warn("something went wrong");
			return EXIT_FAILURE;
		}
		
		okay("PEB patched successfully");

	}

	info("executing malicious code");
	MessageBoxW(NULL, L"YOU'RE IN TROUBLE NOW", L"KAW KAW KAW", (MB_ICONEXCLAMATION | MB_OK));
	return EXIT_SUCCESS;
	
}
