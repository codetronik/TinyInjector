#pragma once
#include <stdio.h>

uint64_t CallMmap(pid_t pid, size_t length);
uint64_t CallMunmap(pid_t pid, uint64_t addr, size_t length);
uint64_t CallDlopen(pid_t pid, const char* library_path);
void CallDlerror(pid_t pid);
void InjectLibrary(pid_t pid, const char* library_path);

