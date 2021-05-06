#include <iostream>
#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "utils.h"

pid_t GetPid(const char* process_name)
{
    if (process_name == NULL)
    {
        return -1;
    }
    DIR* dir = opendir("/proc");
    if (dir == NULL)
    {
        return -1;
    }
    struct dirent* entry;
    while((entry = readdir(dir)) != NULL)
    {
        size_t pid = atoi(entry->d_name);
        if (pid != 0)
        {
            char file_name[30];
            snprintf(file_name, 30, "/proc/%zu/cmdline", pid);
            FILE *fp = fopen(file_name, "r");
            char temp_name[50];
            if (fp != NULL)
            {
                fgets(temp_name, 50, fp);
                fclose(fp);
                if (strcmp(process_name, temp_name) == 0)
                {
                    return pid;
                }
            }
        }
    }
    return -1;
}

bool IsSelinuxEnabled()
{
    bool result = false;
    FILE* fp = fopen("/proc/filesystems", "r");
    char line[100];
    while(fgets(line, 100, fp))
    {
        if (strstr(line, "selinuxfs"))
        {
            result = true;
        }
    }
    fclose(fp);
    return result;
}

void DisableSelinux()
{
    FILE* fp = fopen("/proc/mounts", "r");
    char line[1024] = {0, };
    while(fgets(line, 1024, fp))
    {
        if (strstr(line, "selinuxfs"))
        {
            strtok(line, " ");
            char* selinux_dir = strtok(NULL, " ");
            // 아마도 /sys/fs/selinux/enforce가 됨
            char* selinux_path = strcat(selinux_dir, "/enforce");
            FILE* fp_selinux = fopen(selinux_path, "w");
            char buf[2] = "0"; // set selinux to permissive
            fwrite(buf, strlen(buf), 1, fp_selinux);
            fclose(fp_selinux);
            break;
        }
    }
    fclose(fp);
}

uint64_t GetModuleBaseAddr(pid_t pid, const char* module_name)
{
    uint64_t base_addr_long = 0;

    char file_name[255] = {0, };
    snprintf(file_name, 255, "/proc/%d/maps", pid);
    FILE* fp = fopen(file_name, "r");

    if (fp == NULL)
    {
        return 0;
    }
    char line[512];
    while(fgets(line, 512, fp) != NULL)
    {
        if (strstr(line, module_name) != NULL)
        {
            char* base_addr = strtok(line, "-");
            base_addr_long = strtoull(base_addr, NULL, 16);
            break;
        }
    }

    fclose(fp);
    return base_addr_long;
}

uint64_t GetRemoteFuctionAddr(pid_t remote_pid, const char* module_name, uint64_t local_function_addr)
{
    pid_t pid = getpid();
    uint64_t local_base_addr = GetModuleBaseAddr(pid, module_name);
    uint64_t remote_base_addr = GetModuleBaseAddr(remote_pid, module_name);
    if (local_base_addr == 0 || remote_base_addr == 0)
    {
        return 0;
    }
    return local_function_addr + (remote_base_addr - local_base_addr);
}
