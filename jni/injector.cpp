#include <iostream>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "injector.h"
#include "ptrace.h"
#include "utils.h"

uint64_t CallMmap(pid_t pid, size_t length)
{
    uint64_t function_addr = GetRemoteFuctionAddr(pid, "/apex/com.android.runtime/lib64/bionic/libc.so", ((long) (void*)mmap));
    uint64_t params[6];
    params[0] = 0;
    params[1] = length;
    params[2] = PROT_READ | PROT_WRITE;
    params[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    params[4] = 0;
    params[5] = 0;

    printf("mmap called, function address %lx process %d size %zu\n", function_addr, pid, length);

    return CallRemoteFunction(pid, function_addr, params, 6);
}

uint64_t CallMunmap(pid_t pid, uint64_t addr, size_t length)
{
    uint64_t function_addr = GetRemoteFuctionAddr(pid, "/apex/com.android.runtime/lib/bionic/libc.so", ((long) (void*)munmap));
    uint64_t params[2];
    params[0] = addr;
    params[1] = length;
    printf("munmap called, function address %lx process %d address %lx size %zu\n", function_addr, pid, addr, length);

    return CallRemoteFunction(pid, function_addr, params, 2);
}

uint64_t CallDlopen(pid_t pid, const char* library_path)
{
    uint64_t function_addr = GetRemoteFuctionAddr(pid, "/apex/com.android.runtime/lib64/bionic/libdl.so", (uint64_t)dlopen);
    uint64_t mmap_ret = CallMmap(pid, 0x400);
    PtraceWrite(pid, (uint8_t*)mmap_ret, (unsigned char*)library_path, strlen(library_path) + 1);
    uint64_t params[2];
    params[0] = mmap_ret;
    params[1] = RTLD_NOW | RTLD_LOCAL;

    printf("dlopen called, function address %lx process %d library path %s\n", function_addr, pid, library_path);
    uint64_t ret = CallRemoteFunction(pid, function_addr, params, 2);

    CallMunmap(pid, mmap_ret, 0x400);
    return ret;
}


void CallDlerror(pid_t pid)
{
    uint64_t function_addr = GetRemoteFuctionAddr(pid, "/apex/com.android.runtime/lib64/bionic/libdl.so", (uint64_t)dlerror);
    uint64_t ret = CallRemoteFunction(pid, function_addr, NULL, 0);

    int i = 0;
    char err_msg[512] = {0, };
    while(1)
    {
        long val = ptrace(PTRACE_PEEKDATA, pid, ret+i, NULL);
        if (val == 0) break;
        // 8바이트씩 복사
        memcpy(err_msg+i, &val, 8);
        i=i+8;
    }
    printf("%s\n", err_msg);

}

void InjectLibrary(pid_t pid, const char* library_path)
{
    PtraceAttach(pid);
    uint64_t so_handle = CallDlopen(pid, library_path);

    if (!so_handle)
    {
        CallDlerror(pid);
        printf("Injection failed.\n");
    }
    else
    {
        printf("Injection ended succesfully.\n");
    }

    PtraceDetach(pid);
}
