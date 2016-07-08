/*
 * Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
 * this work by or on behalf of the U.S. Government. 
 * NOTICE:
 * For five (5) years from  the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, and perform publicly and display publicly, by or on behalf of the Government. There is provision for the possible extension of the term of this license. Subsequent to that period or any extension granted, the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, distribute copies to the public, perform publicly and display publicly, and to permit others to do so. The specific term of the license can be identified by inquiry made to Sandia Corporation or DOE.
 * NEITHER THE UNITED STATES GOVERNMENT, NOR THE UNITED STATES DEPARTMENT OF ENERGY, NOR SANDIA CORPORATION, NOR ANY OF THEIR EMPLOYEES, MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LEGAL RESPONSIBILITY FOR THE ACCURACY, COMPLETENESS, OR USEFULNESS OF ANY INFORMATION, APPARATUS, PRODUCT, OR PROCESS DISCLOSED, OR REPRESENTS THAT ITS USE WOULD NOT INFRINGE PRIVATELY OWNED RIGHTS.
 * Any licensee of this software has the obligation and responsibility to abide by the applicable export control laws, regulations, and general prohibitions relating to the export of technical data. Failure to obtain an export control license or other authority from the Government may result in criminal liability under U.S. laws.
 * 
 * This file is the source code of cuckoohooks.dylib for the darwin analyzer of the Cuckoo sandbox.
 * Using process injection, it hooks system calls of interest to monitor for activity.
 * The full list of syscalls is in sys/syscall.h
 * It is compiled using the commands:
 * gcc -fno-common -c cuckoohooks.c
 * gcc -dynamiclib -o cuckoohooks.dylib cuckoohooks.o
 * or, for a 32-and-64-bit one:
 * gcc -fno-common -c cuckoohooks.c -arch i386
 * gcc -dynamiclib -o cuckoohooks_32.dylib cuckoohooks.o -arch i386
 * gcc -fno-common -c cuckoohooks.c -arch x86_64
 * gcc -dynamiclib -o cuckoohooks_64.dylib cuckoohooks.o -arch x86_64
 * lipo -create cuckoohooks_32.dylib cuckoohooks_64.dylib -output cuckoohooks.dylib
 *
 * A makefile is included for convenience
 * It is injected at runtime into the desired process with:
 * DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=<path>/cuckoohooks.dylib ./<executable>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <time.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <arpa/inet.h>
#include <spawn.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>

#include "cuckoohooks.h"

#define LOGFOLDER "/tmp/"
#define F_LOGFILE "file_activity.log"
#define W_LOGFILE "file_writes.log"
#define C_LOGFILE "file_creation.log"
#define D_LOGFILE "file_deletion.log"

int got_config = 0;
int pipe_open = 0;

/*
 * This section contains the hooked syscalls.
 */

/*
 * The open(2) syscall hook. The "..." means this function takes an unspecified number of variables.
 * We are mostly interested in files being created and files being written, so that we can inform Cuckoo about them.
 * However, the function will also log all files read, for completeness.
 * https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man2/open.2.html#//apple_ref/doc/man/2/open
 */

int open(const char *path, int oflag,...) {
    bool was_create;
    //fprintf(stderr, "Starting open within pid %d and file %s and mode %d\n", getpid(), path, oflag);
    //get a pointer to the real function so we can call it from this wrapper
    int (*real_open)(const char*, int, ...) =
    (int (*)(const char*, int,...)) dlsym(RTLD_NEXT, "open");

    //log the file and its flags to the logfile
    char* log = timestamp();
    char* front = append_strings(log, ": ");
    if (in_logfolder(path)) {
        switch(oflag & O_ACCMODE) {
            case O_RDONLY:
                write_to_file(append_strings(front, append_strings("Read - ", path)), "FILE_ACTIVITY:");
            case O_WRONLY:
                write_to_file(append_strings(front, append_strings("Write - ", path)), "FILE_ACTIVITY:");
            case O_RDWR:
                write_to_file(append_strings(front, append_strings("ReadWrite - ", path)), "FILE_ACTIVITY:");
        }
    }

    //printf("File %s opened with %d\n", path, oflag); //for debugging
    
    //The most essential unnamed argument is the file permissions, so we need to pass that to the real open
    va_list args;
    va_start(args,oflag); //list of unnamed arguments
    int perm = va_arg(args, int); //permissions
    va_end(args);
    
    //check to see if the "create if not exists" flag is set
    //and also if the file exists
    if (((oflag & O_CREAT) != 1) & (file_exists(path) == 0) & in_logfolder(path)) {
        //then log that this file was created
        write_to_file(append_strings(front, path), "FILE_CREATE:");
    }

    //call the real function for the results
    int result = real_open(path, oflag, perm);
    if (result == -1) { //if there was an error, note it
         write_to_file(append_strings(front, append_strings("Open failed on ", path)), "FILE_ACTIVITY:");
    }
    return result;
}

/*
 * The creat() call is not a system call, but it is hooked for thoroughness.
 * Header can be found  in fcntl.h
 *
 */

int	creat(const char *pathname, mode_t mode) {
    //get a pointer to the real function so we can call it from this wrapper
    int (*real_creat)(const char*, mode_t) =
    (int (*)(const char*, mode_t)) dlsym(RTLD_NEXT, "creat");
    
    if (in_logfolder(pathname)) {
        //write to the logfile of created files
        char* log = timestamp();
        char* front = append_strings(log, ": ");
        write_to_file(append_strings(front, pathname), "FILE_CREATE:");
    }
    
    return real_creat(pathname, mode);
    
}

/*
 * The unlink command is basically the "delete file" command.
 * In this case, we save all files to be deleted to the ~/tmp folder
 * before doing the delete. These are then exported back to cuckoo for reference.
 * https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man2/unlink.2.html
 */

int unlink(const char *path) {
    //get a pointer to the real function so we can call it from this wrapper
    int (*real_unlink)(const char*) =
    (int (*)(const char*)) dlsym(RTLD_NEXT, "unlink");
    
    //write the file to the log
    char* log = timestamp();
    char* front = append_strings(log, ": ");
    write_to_file(append_strings(front, path), "FILE_DELETE:");
    
    //copy the file into our results folder
    copy_file(path, g_config.results);
    
    return real_unlink(path);
}

/*
 * The rename command, also serves as the "move" command. The new file name
 * is considered to be a "created" file and the old one is considered a "deleted"
 * file, so the end result will have two copies of the file, one under each name.
 * https://developer.apple.com/library/ios/documentation/System/Conceptual/ManPages_iPhoneOS/man2/rename.2.html
 */
int rename(const char *old, const char *new) {
    //get a pointer to the real function so we can call it from this wrapper
    int (*real_rename)(const char*, const char*) =
    (int (*)(const char*, const char*)) dlsym(RTLD_NEXT, "rename");
    
    //write the "old" file to the deleted log
    char* log = timestamp();
    char* front = append_strings(log, ": ");
    write_to_file(append_strings(front, old), "FILE_DELETE:");
    
    //copy the file into our results folder
    copy_file(old, g_config.results);
    
    //write the "new" file to the list of created files
    write_to_file(append_strings(front, new), "FILE_CREATE:");
    
    return real_rename(old, new);
}

/*
 * The hooks of the write functions are there to log what files are actually changed.
 * Changed files will also be extracted by Cuckoo
 * https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man2/write.2.html
 */

ssize_t write(int fildes, const void *buf, size_t nbyte) {
    //get a pointer to the real function so we can call it from this wrapper
    ssize_t (*real_write)(int, const void *, size_t) =
    (ssize_t (*)(int, const void *, size_t)) dlsym(RTLD_NEXT, "write");
    if (nbyte > 0) { //if we are actually writing something
        //get file name from descriptor
        char path[MAXPATHLEN];
        if ((fcntl(fildes, F_GETPATH, path) != -1) & in_logfolder(path))
        {
            //log to the writes log file
            char* log = timestamp();
            char* front = append_strings(log, ": ");
            write_to_file(append_strings(front, path), "FILE_WRITE:");
            //write the bytes to the log file
            char* data = buffer_to_hex(buf, nbyte, 0);
            write_to_file(append_strings("Bytes Written: ", data), "FILE_WRITE:");
            //copy over the file to the results folder
            copy_file(path, g_config.results);
        }
    }
    
    return real_write(fildes, buf, nbyte);
}

ssize_t pwrite(int fildes, const void *buf, size_t nbyte, off_t offset) {
    //get a pointer to the real function so we can call it from this wrapper
    ssize_t (*real_pwrite)(int, const void *, size_t, off_t) =
    (ssize_t (*)(int, const void *, size_t, off_t)) dlsym(RTLD_NEXT, "pwrite");
    
    if (nbyte > 0) { //if we are actually writing something
        //get file name from descriptor
        char path[MAXPATHLEN];
        if ((fcntl(fildes, F_GETPATH, path) != -1) & in_logfolder(path))
        {
            //log to the writes log file
            char* log = timestamp();
            char* front = append_strings(log, ": ");
            write_to_file(append_strings(front, path), "FILE_WRITE:");
            //write the bytes to the log file
            char* data = buffer_to_hex(buf, nbyte, offset);
            write_to_file(append_strings("Bytes Written: ", data), "FILE_WRITE:");
            //copy over the file to the results folder
            copy_file(path, g_config.results);
        }
    }
    return real_pwrite(fildes, buf, nbyte, offset);
}

ssize_t writev(int fildes, const struct iovec *iov, int iovcnt) {
    //get a pointer to the real function so we can call it from this wrapper
    ssize_t (*real_writev)(int, const struct iovec, int) =
    (ssize_t (*)(int, const struct iovec, int)) dlsym(RTLD_NEXT, "writev");
     
     //get file name from descriptor
     char path[MAXPATHLEN];
     if ((fcntl(fildes, F_GETPATH, path) != -1) & in_logfolder(path))
     {
         //log to the writes log file
         char* log = timestamp();
         char* front = append_strings(log, ": ");
         write_to_file(append_strings(front, path), "FILE_WRITE:");
         //copy over the file to the results folder
         copy_file(path, g_config.results);
     }
     
     return real_writev(fildes, *iov, iovcnt);
}

/*
 * Ptrace is of interest because processes calling ptrace with the
 * PT_DENY_ATTACH request can avoid being probed for debugging with Dtrace.
 * This request sets the P_LNOATTACH flag, which is checked by Dtrace.
 * Since Dtrace is a nice tool and we want use it, we can't have that.
 * So any PT_DENY_ATTACH request that comes through gets blocked.
 * https://developer.apple.com/library/ios/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ptrace.2.html
 * http://dtrace.org/blogs/ahl/2008/01/18/mac-os-x-and-the-missing-probes/
 */
int ptrace(int request, pid_t pid, caddr_t addr, int data) {
    //get a pointer to the real function so we can call it from this wrapper
    int (*real_ptrace)(int, pid_t, caddr_t, int) =
    (int (*)(int, pid_t, caddr_t, int)) dlsym(RTLD_NEXT, "ptrace");
    
    //log to the writes log file
    char* log = timestamp();
    char* front = append_strings(log, ": ");
    write_to_file(front, "PTRACE:");
    
    if (request == PT_DENY_ATTACH) { //PT_DENY_ATTACH=31
        return 0; //do nothing for this request
    }
    else {
        return real_ptrace(request, pid, addr, data);
    }
}

/*
 * Vfork is the more memory-effecient version of fork. Hooking this allows
 * us to track new spawned processes.
 * https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man2/vfork.2.html
 */
pid_t vfork(void) {

    //get a pointer to the real function so we can call it from this wrapper
    pid_t (*real_vfork)() =
    (pid_t (*)()) dlsym(RTLD_NEXT, "vfork");
    
    //get the new pid
    pid_t new_process = real_vfork();
    //suspend the process so the injection can happen
    if(new_process > 0) {
        kill(new_process, SIGSTOP);
        //write the new process pid to the pipe
        //The analyzer will add tracking when the command is read
        char* log = timestamp();
        char* front = append_strings(log, ": ");
        sprintf(front, " %d", new_process);
        write_to_file(front, "PROCESS:");
    }
    
    return new_process;

}

/*
 * https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man2/fork.2.html#//apple_ref/doc/man/2/fork
 */
pid_t fork(void) {
    //get a pointer to the real function so we can call it from this wrapper
    pid_t (*real_fork)() =
    (pid_t (*)()) dlsym(RTLD_NEXT, "fork");
    
    //get the new pid
    pid_t new_process = real_fork();
    //suspend the process so the injection can happen
    if(new_process > 0) {
        kill(new_process, SIGSTOP);
        //write the new process pid to the pipe
        //The analyzer will add tracking when the command is read
        char* log = timestamp();
        char* front = append_strings(log, ": ");
        sprintf(front, " %d", new_process);
        write_to_file(front, "PROCESS:");
    }
    else if (new_process == 0) { // Stopping the new process from both the old thread and the new one is necessary for this to work consistently
        kill(getpid(), SIGSTOP);
    }
    
    return new_process;
}

/*
 * posix_spawn is what is most commonly used on OS X, since the Cocoa library uses it by default.
 * https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man2/posix_spawn.2.html
 */
int posix_spawn(pid_t *restrict pid, const char *restrict path,
                const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp,
                char *const argv[restrict], char *const envp[restrict]) {

    //get a pointer to the real function so we can call it from this wrapper
    int (*real_posix_spawn)(pid_t *restrict, const char *restrict,
                            const posix_spawn_file_actions_t, const posix_spawnattr_t *restrict,
                            char *const *restrict, char *const *restrict) =
    (int (*)(pid_t *restrict, const char *restrict,
             const posix_spawn_file_actions_t, const posix_spawnattr_t *restrict,
             char *const *restrict, char *const *restrict)) dlsym(RTLD_NEXT, "posix_spawn");
    
    //insert the injected library into the new process' environment variables
    char* environ[3];
    environ[0] = "DYLD_FORCE_FLAT_NAMESPACE=1";
    environ[1] = append_strings("DYLD_INSERT_LIBRARIES=", getenv("DYLD_INSERT_LIBRARIES"));
    
    int result;
    //get the result - the pid will be saved in the pid argument struct
    if (!envp) { //if no arguments were passed, just use our array
        environ[2] = NULL;
        result = real_posix_spawn(pid, path, file_actions, attrp, argv, environ);
    }
    else {
        //calculate the size of the given array
        int size = 0;
        //we know the array is null-terminated, so we look for that to get the size
        char* item = envp[0];
        while (item) {
            size++;
            item = envp[size];
        }
        size++;
        char* both[2+size];
        int i;
        int flag1 = 0;
        int flag2 = 0;
        //copy the given envp array into the new one
        for (i = 0; i < size-1; i++) {
            //avoid duplicate environment variables
            if(strstr(envp[i], "DYLD_FORCE_FLAT_NAMESPACE")) {
                flag1 = 1;
            }
            if (strstr(envp[i], "DYLD_INSERT_LIBRARIES=")) {
                flag2 = 1;
            }
            both[i] = envp[i];
        }
        //if necessary, add in the injected library environment variables
        if (flag1 == 0) {
            both[i] = environ[0];
            i++;
        }
        if (flag2 == 0) {
            both[i] = environ[1];
            i++;
        }
        both[i] = NULL; //terminate the array (doesn't matter if it's not the end)

        result = real_posix_spawn(pid, path, file_actions, attrp, argv, both);
    }
    //suspend the process so the injection can happen
    if (*pid > 0) {
        kill(*pid, SIGSTOP);
    }
    
    //write the new process pid to the pipe
    //The analyzer will add tracking when the command is read
    char* log = timestamp();
    char* front = append_strings(log, ": ");
    sprintf(front, " %d", *pid);
    write_to_file(front, "PROCESS:");
    
    return result;
    
}

int posix_spawnp(pid_t *restrict pid, const char *restrict file,
                 const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp,
                 char *const argv[restrict], char *const envp[restrict]) {

    //get a pointer to the real function so we can call it from this wrapper
    int (*real_posix_spawnp)(pid_t *restrict, const char *restrict,
                            const posix_spawn_file_actions_t, const posix_spawnattr_t *restrict,
                            char *const *restrict, char *const *restrict) =
    (int (*)(pid_t *restrict, const char *restrict,
             const posix_spawn_file_actions_t, const posix_spawnattr_t *restrict,
             char *const *restrict, char *const *restrict)) dlsym(RTLD_NEXT, "posix_spawnp");
    
    //insert the injected library into the new process' environment variables
    char* environ[3];
    environ[0] = "DYLD_FORCE_FLAT_NAMESPACE=1";
    environ[1] = append_strings("DYLD_INSERT_LIBRARIES=", getenv("DYLD_INSERT_LIBRARIES"));
    
    int result;
    //get the result - the pid will be saved in the pid argument struct
    if (!envp) { //if no arguments were passed, just use our array
        environ[2] = NULL;
        result = real_posix_spawnp(pid, file, file_actions, attrp, argv, environ);
    }
    else {
        //calculate the size of the given array
        int size = 0;
        //we know the array is null-terminated, so we look for that to get the size
        char* item = envp[0];
        while (item) {
            size++;
            item = envp[size];
        }
        size++;
        char* both[2+size];
        int i;
        int flag1 = 0;
        int flag2 = 0;
        //copy the given envp array into the new one
        for (i = 0; i < size-1; i++) {
            //avoid duplicate environment variables
            if(strstr(envp[i], "DYLD_FORCE_FLAT_NAMESPACE")) {
                flag1 = 1;
            }
            if (strstr(envp[i], "DYLD_INSERT_LIBRARIES=")) {
                flag2 = 1;
            }
            both[i] = envp[i];
        }
        //if necessary, add in the injected library environment variables
        if (flag1 == 0) {
            both[i] = environ[0];
            i++;
        }
        if (flag2 == 0) {
            both[i] = environ[1];
            i++;
        }
        both[i] = NULL; //terminate the array (doesn't matter if it's not the end)
        
        result = real_posix_spawnp(pid, file, file_actions, attrp, argv, both);
    }
    //suspend the process so the injection can happen
    if (*pid > 0) {
        kill(*pid, SIGSTOP);
    }
    
    //write the new process pid to the pipe
    //The analyzer will add tracking when the command is read
    char* log = timestamp();
    char* front = append_strings(log, ": ");
    sprintf(front, " %d", *pid);
    write_to_file(front, "PROCESS:");
    
    return result;
    
}

/*int execve(const char *path, char *const argv[], char *const envp[]) {
    //get a pointer to the real function so we can call it from this wrapper
    int (*real_execve)(const char *, char *const *, char *const *) =
    (int (*)(const char *, char *const *, char *const *)) dlsym(RTLD_NEXT, "execve");
    
    char* log = timestamp();
    char* front = append_strings(log, ": ");
    sprintf(front, " %s", path);
    write_to_file(front, "EXEC:");

    return real_execve(path, argv, envp);
}*/



/*
 * This section contains utility functions used by the hooks.
 */

/*
 * Prints a string to the log file, with error handling.
 * By default it is just appended.
 */
void write_to_file(const char* str, const char* command) {
    //if we don't have the name of pipe, read it
    if (got_config == 0) {
        read_config();
        got_config = 1;
    }
    struct timespec tim, tim2;
    tim.tv_sec = 0;
    tim.tv_nsec = 50000000L;
    while (pipe_open == 1) {
        nanosleep(&tim , &tim2);
    }
    pipe_open = 1;
    //open the pipe for writing
    FILE *p = fopen(g_config.pipe_name, "w");
    if (p == NULL)
    {
        return;
        //fprintf(stderr, "Error opening pipe %s.\n", g_config.pipe_name);
        //exit(1);
    }
    //write to the file
    fprintf(p, "%s", command);
    fprintf(p, "%s", str);
    fprintf(p, "%s", "\n");
    fflush(p);
    //close the file
    fclose(p);
    pipe_open = 0;
}

/*
 * Appends two strings, because C is evil.
 */
char* append_strings(const char* str1, const char* str2) {
    char* result;
    if((result = malloc(strlen(str1)+strlen(str2)+1)) != NULL){
        result[0] = '\0';   // ensures the memory is an empty string
        //concatenate strings
        strcat(result,str1);
        strcat(result,str2);
        return result;
    } else { //if we run out of memory, which hopefully doesn't happen
        return "";
        //fprintf(stderr,"Could not allocate memory for strings.\n");
        //exit(1);
    }
}

/*
 * Checks if a file exists, used to see if something is being created.
 * Return 1 if the files exists, 0 if not.
 */
int file_exists(const char* path) {
    FILE* f;
    if ((f = fopen(path, "r")) == NULL) { //file was not opened
        if (errno == ENOENT) {
            return 0; //file does not exist
        } else {
            return 1; //file may exist, but there were other errors.
        }
    } else {
        fclose(f);
    }
    return 1;
}

/*
 * Copies the file at "src" into the file at "dest".
 * Note: It will overwrite "dest" if it already exists.
 */
void copy_file(const char* src, const char* dest) {
    unsigned char buffer[4096];
    int err, n;
    
    //get the file name from the path and append it to dest
    dest = append_strings(dest, basename(src));
    
    //open the two files
    int src_file = open(src, O_RDONLY);
    int dest_file = open(dest, O_CREAT|O_WRONLY, 0777);
    
    //write in the bytes 4096 at a time from src to dest
    while (1) {
        err = read(src_file, buffer, 4096);
        if (err == -1) {
            //printf("COPY FILE ERROR (src): %s on file %s\n", strerror(errno), src);
            break;
        }
        n = err;
        
        if (n == 0) break; //stop when we read all of the file
        
        err = write(dest_file, buffer, n);
        if (err == -1) {
            //printf("COPY FILE ERROR (dest): %s on file %s\n", strerror(errno), dest);
            break;
        }
    }
    //close both files
    close(src_file);
    close(dest_file);
}

/* Returns the current time in human-readable format for logging */
char* timestamp() {
    char * result = malloc(24);
    time_t ltime;
    ltime=time(NULL); //get calendar time
    sprintf(result, "%s",asctime(localtime(&ltime)));
    result[strcspn(result,"\n")] = '\0'; //strip newlines
    
    //add the pid
    char str[15];
    sprintf(str, " (%d)  ", getpid());
    return append_strings(result, str);
}

/* Returns 1 if the action is not in the logging folder
 * and 0 if it is, to avoid logging the injected library's actions.
 */
int in_logfolder(const char *path) {
    //if we don't have the name of the results folder, read it
    if (got_config == 0) {
        read_config();
        got_config = 1;
    }
    if((strstr(path, g_config.results) != NULL) ||  (strstr(path, g_config.pipe_name) != NULL)) { //folder is in path
        return 0;
    }
    else { //folder is not in path
        return 1;
    }
}

/*
 * Read in the configuration file for this process, created by api/process.py
 * This is a modified verison of the function found in https://github.com/cuckoobox/cuckoomon/blob/master/config.c
 */
void read_config() {
    
    char buf[512], config_fname[PATH_MAX];
    sprintf(config_fname, "%s%d.conf", getenv("TMPDIR"), getpid());
    FILE *fp = fopen(config_fname, "r");

    if (fp == NULL) {
        sprintf(config_fname, "%s%d.conf", getenv("TMPDIR"), getppid());
        FILE *fp2 = fopen(config_fname, "r");
    }
    

    if(fp != NULL) {
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            // cut off the newline
            char *p = strchr(buf, '\r');
            if(p != NULL) *p = 0;
            p = strchr(buf, '\n');
            if(p != NULL) *p = 0;
            // split key=value
            p = strchr(buf, '=');
            if(p != NULL) {
                *p = 0;
                
                const char *key = buf, *value = p + 1;
                if(!strcmp(key, "pipe")) {
                    strncpy(g_config.pipe_name, value,
                            ARRAYSIZE(g_config.pipe_name));
                }
                else if(!strcmp(key, "results")) {
                    strncpy(g_config.results, value,
                            ARRAYSIZE(g_config.results));
                }
                else if(!strcmp(key, "analyzer")) {
                    strncpy(g_config.analyzer, value,
                            ARRAYSIZE(g_config.analyzer));
                }
                else if(!strcmp(key, "first-process")) {
                    g_config.first_process = value[0] == '1';
                }
                else if(!strcmp(key, "startup-time")) {
                    g_config.startup_time = atoi(value);
                }
                else if(!strcmp(key, "retaddr-check")) {
                    g_config.retaddr_check = value[0] == '1';
                }
                else if(!strcmp(key, "host-ip")) {
                    g_config.host_ip = inet_addr(value);
                }
                else if(!strcmp(key, "host-port")) {
                    g_config.host_port = atoi(value);
                }
            }
        }
        fclose(fp);

        int (*real_unlink)(const char*) =
        (int (*)(const char*)) dlsym(RTLD_NEXT, "unlink");
        //real_unlink(config_fname);
    }
}

/*
 * Converts byte buffers to hex so we can see what the program is writing.
 */
char* buffer_to_hex(const void *buf, size_t size, off_t offset) {
    //sometimes files try to request a ridiculous amount to write, so we only do the first 100 bytes
    if (size > 100) {
        size = 100;
    }
    //copy the buffer
    const void *buf2[size];
    memcpy (buf2, buf, size);
    //make the buffer - each byte will be converted to the form \x<hex>, so 4 chars each
    char * result = malloc((size*4)+1);
    int pos = 0;
    while(size > 0) {
        size--;
        sprintf(result+pos, "\\x%.2x", *((unsigned char*)&(buf[offset])));
        offset++;
        pos += 4;
    }
    return result;
}


