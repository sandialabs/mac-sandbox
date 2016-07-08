"""
Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
this work by or on behalf of the U.S. Government. 
NOTICE:
For five (5) years from  the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, and perform publicly and display publicly, by or on behalf of the Government. There is provision for the possible extension of the term of this license. Subsequent to that period or any extension granted, the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, distribute copies to the public, perform publicly and display publicly, and to permit others to do so. The specific term of the license can be identified by inquiry made to Sandia Corporation or DOE.
NEITHER THE UNITED STATES GOVERNMENT, NOR THE UNITED STATES DEPARTMENT OF ENERGY, NOR SANDIA CORPORATION, NOR ANY OF THEIR EMPLOYEES, MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LEGAL RESPONSIBILITY FOR THE ACCURACY, COMPLETENESS, OR USEFULNESS OF ANY INFORMATION, APPARATUS, PRODUCT, OR PROCESS DISCLOSED, OR REPRESENTS THAT ITS USE WOULD NOT INFRINGE PRIVATELY OWNED RIGHTS.
Any licensee of this software has the obligation and responsibility to abide by the applicable export control laws, regulations, and general prohibitions relating to the export of technical data. Failure to obtain an export control license or other authority from the Government may result in criminal liability under U.S. laws.

Provides the dylib injection functionality and a wrapper for process execution.
The classes that extend this for different file types are found in darwin/modules/packages.
"""

import os
import logging
import random
import sys
import time
import subprocess
from shutil import copy
import signal

from lib.common.rand import random_string
from lib.common.constants import PATHS, PIPE, SHUTDOWN_MUTEX
from lib.core.config import Config #parses the analysis.conf configuration file

log = logging.getLogger(__name__)

#This is the all-important list of APIs to trace
#There is an overhead for each one you add, so choose them carefully. Some examples are below.
api_traces = ["libSystem*", #provides libc API as well as access to kernel methods and low-level system calls
              "CoreFoundation", #Provides primitives, data structures, etc.
              "Foundation", #data structure support
              "CoreServices", #access to things like Bonjour, Spotlight, AppleEvents, etc.
              "libgcc*", #gcc, obviously
              ]

def randomize_dylib(dylib_path):
    """Randomize dylib name, to prevent easy detection by malware.
    @return: new dylib path.
    """
    new_dylib_name = random_string(6) # generate a random name
    # make a path to the random name in the current working directory
    new_dylib_path = os.path.join(os.getcwd(), "dylib", "{0}.dylib".format(new_dylib_name))

    try:
        # copy the dylib file to the new path in the current working directory
        copy(dylib_path, new_dylib_path)
        return new_dylib_path
    except: #if this fails, just return the old path
        return dylib_path

class Process:
    """ OS X process """
    first_process = True
    cuckoohooks = "cuckoohooks.dylib"
    startup_time = 0

    def __init__(self, pid=0, h_process=None, thread_id=0, h_thread=0):
        """@param pid: PID.
        @param h_process: process handle.
        @param thread_id: thread id.
        @param h_thread: thread handle.
        """
        self.pid = pid
        self.h_process = h_process
        self.thread_id = thread_id
        self.h_thread = h_thread
        self.suspended = True #assume it is suspended to start with
        self.event_handle = None
        self.is_tracing = False

    def execute(self, path, args=None, suspended=False):
        """Execute sample process.
        @param path: sample path.
        @param args: process args.
        @param suspended: is suspended.
        @return: operation status.
        """
        #check to make sure the file is accessible
        if os.access(path, os.F_OK):
            log.info("File exists at path \"%s\"", path)

        #by default you can't execute in the /tmp directory, so have to change permissions
        i = 0
        while not os.access(path, os.X_OK) and i < 2:
            os.chmod(path, 0755)
            i += 1
        if not os.access(path, os.X_OK):
            log.error("No permissions to execute file at path \"%s\", "
                      "execution aborted", path)
            return False

        # fork a child process
        # Note: this could also be done with the subprocess or multiprocessing modules
        # but neither of them gave the independence I was looking for.
        try:
            newpid = os.fork()
        except OSError, e:
            log.error("Failed to execute process from path \"%s\" with "
                      "arguments \"%s\" (Error: %s)", path, args, e)
            return False

        # randomize the hooking library name
        dylib = randomize_dylib(os.path.join("dylib", self.cuckoohooks))

        if newpid == 0: #if this is the child process
            #set the environment variables for the syscall hook injection
            new_environ = os.environ
            new_environ['DYLD_FORCE_FLAT_NAMESPACE'] = '1'
            new_environ['DYLD_INSERT_LIBRARIES'] = dylib
            log.info("Child process with pid %d", os.getpid())
            self.pid = os.getpid()

            Process.first_process = False
            # set the sid to make this child process independent of the parent
            os.setsid()

            # wait for traces to be initialized
            app_log = os.path.join(PATHS["logs"], "api_calls_"+str(self.pid)+".log")
            while not os.path.exists(app_log):
                time.sleep(0.3)
            # execute the given executable
            if args is None:
                os.execve(path, (path,), new_environ)
            else:
                os.execve(path, args, new_environ)

            #exit when finished
            os._exit(0)
        else: #this is in the parent process
            log.info("Parent process with pid %d", os.getpid())
            #store the child process info
            self.pid = newpid
            self.h_process = psutil.Process(self.pid)

            self.start_trace()

            log.info("Successfully executed process from path \"%s\" with "
                     "arguments \"%s\" with pid %d", path, args, self.pid)

            return True

    def start_trace(self):
        """
        Once a process has been started, write the library config file
        and start the system call tracing.
        @return: None
        """

        # write configuration file for injected library
        config_path = os.path.join(os.getenv("TMPDIR"), "%s.conf" % self.pid)
        log.info("Writing configuration file at %s.", config_path)
        with open(config_path, "w") as config:
            cfg = Config("analysis.conf")

            # The first time we come up with a random startup-time.
            if Process.first_process:
                # This adds 1 up to 30 times of 20 minutes to the startup
                # time of the process, therefore bypassing anti-vm checks
                # which check whether the VM has only been up for <10 minutes.
                Process.startup_time = random.randint(1, 30) * 20 * 60 * 1000

            config.write("host-ip={0}\n".format(cfg.ip))
            config.write("host-port={0}\n".format(cfg.port))
            config.write("pipe={0}\n".format(PIPE))
            config.write("results={0}\n".format(PATHS["drop"]+"/"))
            config.write("analyzer={0}\n".format(os.getcwd()))
            config.write("first-process={0}\n".format(Process.first_process))
            config.write("startup-time={0}\n".format(Process.startup_time))
            config.write("shutdown-mutex={0}\n".format(SHUTDOWN_MUTEX))

            Process.first_process = False

        # Start system call tracing
        # Dtruss traces system calls using Dtrace
        pargs = ["dtruss", "-l", "-p", str(self.pid)]
        truss_log = os.path.join(PATHS["logs"], "system_calls_"+str(self.pid)+".log")
        results = open(truss_log, "a+")
        try:
            proc2 = subprocess.Popen(pargs, stdout=results, stderr=results)
            log.info("Starting Dtruss on pid %d", self.pid)
        except (OSError, ValueError):
            log.exception("Failed to start system call monitor.")
        results.close()

        # Wait for initialization lines to appear in log files
        while os.path.getsize(truss_log) == 0:
            time.sleep(0.5)

        # Dapptrace traces API calls using Dtrace. I used my own version modified for performance
        # NOTE: This slows down the program A LOT if you use the -U option (tracks all libraries) instead of -u
        os.chmod("lib/api/apitrace", 0755)
        pargs = ["lib/api/apitrace", "-u", ",".join(api_traces), "-p", str(self.pid)]
        app_log = os.path.join(PATHS["logs"], "api_calls_"+str(self.pid)+".log")
        results2 = open(app_log, "a+")
        try:
            proc1 = subprocess.Popen(pargs, stdout=results2, stderr=results2)
            log.info("Starting apitrace on pid %d", self.pid)
        except (OSError, ValueError):
            log.exception("Failed to start api call monitor.")
        results2.close()

        # wait for initialization lines to appear in log files
        while os.path.getsize(app_log) == 0:
            time.sleep(0.5)


        self.is_tracing = True
        self.resume()

    def is_alive(self):
        """Process is alive?
        @return: process status.
        """
        exists = True
        if not self.h_process:
            exists = self.open()

        if not exists: #program has already exited
            return False

        #make sure the process is both in the table and not a zombie (ie, terminated)
        return self.h_process.is_running() and not (self.h_process.status() == psutil.STATUS_ZOMBIE)

    def get_filepath(self):
        """Get process image file path.
        @return: decoded file path.
        """
        if not self.h_process:
            self.open()

        return self.h_process.name()


    def exit_code(self):
        """Get process exit code.
        @return: exit code value.
        """
        if not self.h_process:
            self.open()

        return os.waitpid(self.pid)

    def open(self):
        """Open a process and/or thread.
        @return: operation status.
        """
        ret = bool(self.pid or self.thread_id)
        if self.pid and not self.h_process:
            try:
                self.h_process = psutil.Process(self.pid)
                ret = True
            except: #unable to get process
                ret = False

        return ret

    def get_parent_pid(self):
        """Get the Parent Process ID."""
        if not self.h_process:
            self.open()

        return self.h_process.ppid()

    def terminate(self):
        """Terminate process.
        @return: operation status.
        """
        if self.h_process == 0:
            self.open()

        pargs = ["kill", str(self.pid)]
        count = 0 #sometimes this requires multiple tries
        while self.h_process.status() == psutil.STATUS_RUNNING:
            # Note: both self.h_process.terminate() and os.kill were unreliable for termination
            log.info("Attempting to kill process " + str(self.pid) + ", attempt " + str(count))
            proc = subprocess.Popen(pargs)
            count +=1
            if count > 5:
                break
        if self.h_process.status() == psutil.STATUS_ZOMBIE or self.h_process.status() == psutil.STATUS_DEAD:
            log.info("Successfully terminated process with pid %d", self.pid)
            return True
        else:
            log.error("Failed to terminate process with pid %d", self.pid)
            return False

    def resume(self):
        """Resume a suspended thread.
        @return: operation status.
        """
        if not self.suspended:
            log.warning("The process with pid %d was not suspended, so it was not resumed"
                        % self.pid)
            return False

        if self.is_tracing: # only resume when Dtrace probes are in place
            pargs = ["kill", "-SIGCONT", str(self.pid)]
            count = 0 #sometimes this requires multiple tries
            while self.h_process.status() == psutil.STATUS_STOPPED:
                # Note: both self.h_process.resume() and os.kill were unreliable for resuming
                log.info("Attempting to resume process " + str(self.pid) + ", attempt " + str(count))
                proc = subprocess.Popen(pargs)
                count +=1
                if count > 5:
                    break
            if self.h_process.status() == psutil.STATUS_RUNNING:
                log.info("Successfully resumed process with pid %d", self.pid)
                return True
            else:
                log.error("Failed to resume process with pid %d", self.pid)
                return False

if __name__ == '__main__':
    print "Why would you do that?"