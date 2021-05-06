#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include "injector.h"
#include "utils.h"

int main(int argc, char const *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s [process name] [library path]\n", argv[0]);
        return -1;
    }
    /*
    char cmd[100] = {0,};
    sprintf(cmd, "killall -9 %s", argv[1]);
    system(cmd);
    */
    pid_t pid;
    printf("waiting process..");
    while(1)
    {
        pid = GetPid(argv[1]);
    	if (pid != -1)
    	{
    		break;
    	}
    }

    const char* process_name = argv[1];
    const char* library_path = argv[2];

    printf("process name: %s, library path: %s, pid: %d\n", process_name, library_path, pid);

/*
    if (IsSelinuxEnabled())
    {
        DisableSelinux();
    }
*/
    InjectLibrary(pid, library_path);
    return 0;
}
