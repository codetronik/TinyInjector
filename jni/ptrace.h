#pragma once
#include <stdio.h>

int PtraceAttach(pid_t pid);
int PtraceDetach(pid_t pid);
void PtraceWrite(pid_t pid, unsigned char* addr, unsigned char* data, size_t size);
uint64_t CallRemoteFunction(pid_t pid, uint64_t function_addr, uint64_t* args, size_t argc); // call function in remote process
