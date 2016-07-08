/*
 * Symbols for cuckoohooks.c
 */

#include <sys/syslimits.h>
#include <sys/_types.h>
#include <sys/_types/_sigset_t.h>
#include <sys/kernel_types.h>
#include <sys/proc_info.h>
#ifndef _cuckoohooks_h
#define _cuckoohooks_h
#define ARRAYSIZE(a) (sizeof(a) / sizeof(*(a)))

struct open_nocancel_args {
	//char path_l_[PADL_(user_addr_t)]; user_addr_t path; char path_r_[PADR_(user_addr_t)];
	//char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	//char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
};

int open(const char *path, int oflag,...);
int	creat(const char *pathname, mode_t mode);
int unlink(const char *path);
int rename(const char *old, const char *new);
ssize_t write(int fildes, const void *buf, size_t nbyte);
ssize_t pwrite(int fildes, const void *buf, size_t nbyte, off_t offset);
ssize_t writev(int fildes, const struct iovec *iov, int iovcnt);
int ptrace(int request, pid_t pid, caddr_t addr, int data);
pid_t vfork(void);
pid_t fork(void);
int posix_spawn(pid_t *restrict pid, const char *restrict path,
            const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp,
            char *const argv[restrict], char *const envp[restrict]);
int posix_spawnp(pid_t *restrict pid, const char *restrict file,
             const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp,
             char *const argv[restrict], char *const envp[restrict]);
//int execve(const char *path, char *const argv[], char *const envp[]);

void write_to_file(const char* str, const char* command);
char* append_strings(const char* str1, const char* str2);
int file_exists(const char* path);
void copy_file(const char* src, const char* dest);
char* timestamp();
int in_logfolder(const char* path);
char* buffer_to_hex(const void *buf, size_t size, off_t offset);

struct {
    // name of the pipe to communicate with cuckoo
    char pipe_name[PATH_MAX];
    
    // results directory, has to be hidden
    char results[PATH_MAX];
    
    // analyzer directory, has to be hidden
    char analyzer[PATH_MAX];
    
    // is this the first process or not?
    int first_process;
    
    // how many milliseconds since startup
    unsigned int startup_time;
    
    // do we want to enable the retaddr check?
    int retaddr_check;
    
    // server ip and port
    unsigned int host_ip;
    unsigned short host_port;
} g_config;

void read_config();

#endif
