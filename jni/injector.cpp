#include <iostream>
#include <dlfcn.h>
#include <string.h>
#include <linux/elf.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include "injector.h"
#include "utils.h"

void PtraceRegs(pid_t pid, int type, struct user_pt_regs *regs)
{
    struct iovec iov = { 0, }; // i/o를 위한 구조체
    iov.iov_base = regs;
    iov.iov_len = sizeof(user_pt_regs);

    ptrace(type, pid, NT_PRSTATUS, &iov);
}

void PtraceWrite(pid_t pid, unsigned char* addr, unsigned char* data, size_t size)
{
    int mod = size % 8;
    int loop_count = size / 8;

    /*
    printf("mod : %d\n", mod);
    printf("loop_count : %d\n", loop_count);
    */
    unsigned char* tmp_addr = addr;
    unsigned char* tmp_data = data;
    for(int i = 0; i < loop_count; ++i)
    {
        // 대상 pid의 tmp_addr(mmap한 메모리 주소)에 8바이트(64bit의 WORD size) 단위로 데이터를 쓴다
        ptrace(PTRACE_POKEDATA, pid, tmp_addr, *((long*)tmp_data));
        tmp_addr += 8;
        tmp_data += 8;
    }
    if (mod > 0)
    {
        // 대상 pid에서 tmp_addr의 데이터를 가져온다
        long val = ptrace(PTRACE_PEEKDATA, pid, tmp_addr, NULL);
        uint8_t* p = (uint8_t*) &val;

        for(int i = 0; i < mod; ++i)
        {
            *p = *(tmp_data);
            p++;
            tmp_data++;
        }
        //printf("p = %lx\n", val);
        ptrace(PTRACE_POKEDATA, pid, tmp_addr, val);
    }
    printf("Write %zu bytes to %p process %d\n", size, addr, pid);

}

uint64_t CallRemoteFunction(pid_t pid, uint64_t function_addr, uint64_t* args, size_t argc)
{
    struct user_pt_regs regs = { 0, };
    struct user_pt_regs backup_regs = { 0, };

    // NT_PRSTATUS : 보통 범용 레지스터를 읽어들임
    PtraceRegs(pid, PTRACE_GETREGSET, &regs);
    /*
    printf("before\n");
    printf("regs.ARM_lr %llx\n", regs.regs[30]);
    printf("regs.ARM_pc %llx\n", regs.pc);
    */
    // 현재 레지스터를 백업함
    memcpy(&backup_regs, &regs, sizeof(struct user_pt_regs));
    /*
    함수 호출 시 파라미터는 최대 8개까지 레지스터(X0~X7)를 통해 전달한다. AArch32는 파라미터
    를 4개까지 레지스터를 통해 저장하고, 초과하는 파라미터는 스택을 통해 전달한다. 레지스터만
    사용하여 파라미터를 전달한다면 외부 메모리에 위치한 스택 접근이 줄어드는 효과가 있다. X0는
    함수의 결과를 리턴하는 용도로도 사용한다.
    */
    for(int i = 0; i < argc; i++)
    {
        regs.regs[i] = args[i];
    }

    // set return addr to 0, so we could catch SIGSEGV(= invalid memory reference)
    // lr : 함수 호출 시 되돌아갈 함수의 주소가 저장되는 레지스터
    regs.regs[30] = 0;
    regs.pc = function_addr;
    PtraceRegs(pid, PTRACE_SETREGSET, &regs);

    // 멈춘 프로세스를 재개한다.
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    /*
    pid에 해당하는 자식 프로세스가 멈춤 상태일 경우 그 상태를 리턴한다.
    즉 프로세스의 종료뿐 아니라 프로세스의 멈춤상태도 찾아낸다.
    */
    waitpid(pid, NULL, WUNTRACED);

    // x0(리턴 value)를 구하는 용도로 사용함
    memset(&regs, 0, sizeof(sizeof(user_pt_regs)));
    PtraceRegs(pid, PTRACE_GETREGSET, &regs);
    // 레지스터를 원복하여 원래 흐름으로 되돌림
    PtraceRegs(pid, PTRACE_SETREGSET, &backup_regs);

    // Fuction return value
    printf("Call remote function %lx with %zu arguments, return value is %llx\n", function_addr, argc, (unsigned long long)regs.regs[0]);

    return regs.regs[0];
}


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
    params[0] = mmap_ret; // library path address
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
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
    {
        printf("attach error : ");
        perror(NULL);
        return;
    }
    waitpid(pid, NULL, WUNTRACED);
    printf("Attached to process %d\n", pid);

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

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
    {
        perror(NULL);
        return;
    }
    printf("Detached from process %d\n", pid);

}
