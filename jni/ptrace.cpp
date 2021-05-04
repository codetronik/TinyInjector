#include <iostream>
#include <linux/elf.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include "ptrace.h"

#define pt_regs  user_pt_regs
#define uregs    regs
#define ARM_r0   regs[0]
#define ARM_lr   regs[30]
#define ARM_sp   sp
#define ARM_pc   pc
#define ARM_cpsr pstate

#define REGS_ARG_NUM    6

static void PtraceGetRegs(pid_t pid, struct pt_regs *regs);
static void PtraceSetRegs(pid_t pid, struct pt_regs *regs);

int PtraceAttach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
    {
        perror(NULL);
        return -1;
    }
    waitpid(pid, NULL, WUNTRACED);
    printf("Attached to process %d\n", pid);

    return 0;
}

int PtraceDetach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
    {
        perror(NULL);
        return -1;
    }
    printf("Detached from process %d\n", pid);
    return 0;
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

static void PtraceGetRegs(pid_t pid, struct pt_regs *regs)
 {
    struct
    {
        void* ufb;
        size_t len;
    } regsvec = { regs, sizeof(struct pt_regs) };

    // NT_PRSTATUS : 보통 범용 레지스터를 읽어들임
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regsvec);

}

static void PtraceSetRegs(pid_t pid, struct pt_regs *regs)
{
    struct
    {
        void* ufb;
        size_t len;
    } regsvec = { regs, sizeof(struct pt_regs) };

    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &regsvec);
}

uint64_t CallRemoteFunction(pid_t pid, uint64_t function_addr, uint64_t* args, size_t argc)
{
    struct pt_regs regs;
    // backup the original regs
    struct pt_regs backup_regs;

    PtraceGetRegs(pid, &regs);
    /*
    printf("regs.ARM_lr %llx\n", regs.ARM_lr);
    printf("regs.ARM_pc %llx\n", regs.ARM_pc);
    */
    memcpy(&backup_regs, &regs, sizeof(struct pt_regs));
    // put the first 4 args to r0-r3
    for(int i = 0; i < argc && i < REGS_ARG_NUM; ++i)
    {
        regs.uregs[i] = args[i];
    }
    // push the remainder to stack
    if (argc > REGS_ARG_NUM) // 6
    {
        printf("tam\n");
        regs.ARM_sp -= (argc - REGS_ARG_NUM) * sizeof(long);
        uint64_t* data = args + REGS_ARG_NUM;
        PtraceWrite(pid, (uint8_t*)regs.ARM_sp, (uint8_t*)data, (argc - REGS_ARG_NUM) * sizeof(long));
    }
    // set return addr to 0, so we could catch SIGSEGV
    regs.ARM_lr = 0;
    regs.ARM_pc = function_addr;
    PtraceSetRegs(pid, &regs);

    // Restart the stopped tracee process.
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    waitpid(pid, NULL, WUNTRACED);

    // to get return value;
    PtraceGetRegs(pid, &regs);
    PtraceSetRegs(pid, &backup_regs); // 레지스터 원복
    // Fuction return value
    printf("Call remote function %lx with %zu arguments, return value is %llx\n", function_addr, argc, (unsigned long long)regs.ARM_r0);

    return regs.ARM_r0;
}
