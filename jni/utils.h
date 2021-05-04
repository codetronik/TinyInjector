#pragma once
#include <stdbool.h>
#include <stdio.h>

pid_t GetPid(const char* process_name); // get pid of specified process
bool IsSelinuxEnabled(); // check the status of SELinux
void DisableSelinux(); // disable SELinux
uint64_t GetModuleBaseAddr(pid_t pid, const char* module_name); // get base address of specified module in given process
uint64_t GetRemoteFuctionAddr(pid_t remote_pid, const char* module_name, uint64_t local_function_addr); // get fuction address in remote process

