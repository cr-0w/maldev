#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

extern PTEB getTEB(void);
extern DWORD CustomError(void);

int main(void) {

	info("getting the TEB");
	PTEB pTEB = getTEB();
	okay("\\___[ TEB\n\t\\_0x%p]\n", pTEB);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1337);

	if (hProcess == NULL) {
		okay("[OpenProcess]  FAILED! (this is a good thing)");
		info("[CustomError]  ERROR: 0x%lx", CustomError());
		info("[GetLastError] ERROR: 0x%lx", GetLastError());

		if (CustomError() == GetLastError()) {
			okay("values matched! custom error function working properly");
			return EXIT_SUCCESS;
		}

		warn("values don't match: 0x%lx", GetLastError());
		return EXIT_FAILURE;
	}

}
