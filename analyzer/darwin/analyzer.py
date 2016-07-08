"""

Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
this work by or on behalf of the U.S. Government. 
NOTICE:
For five (5) years from  the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, and perform publicly and display publicly, by or on behalf of the Government. There is provision for the possible extension of the term of this license. Subsequent to that period or any extension granted, the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, distribute copies to the public, perform publicly and display publicly, and to permit others to do so. The specific term of the license can be identified by inquiry made to Sandia Corporation or DOE.
NEITHER THE UNITED STATES GOVERNMENT, NOR THE UNITED STATES DEPARTMENT OF ENERGY, NOR SANDIA CORPORATION, NOR ANY OF THEIR EMPLOYEES, MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LEGAL RESPONSIBILITY FOR THE ACCURACY, COMPLETENESS, OR USEFULNESS OF ANY INFORMATION, APPARATUS, PRODUCT, OR PROCESS DISCLOSED, OR REPRESENTS THAT ITS USE WOULD NOT INFRINGE PRIVATELY OWNED RIGHTS.
Any licensee of this software has the obligation and responsibility to abide by the applicable export control laws, regulations, and general prohibitions relating to the export of technical data. Failure to obtain an export control license or other authority from the Government may result in criminal liability under U.S. laws.

This is the darwin analyzer for Cuckoo - OS X is built on Darwin, which is a UNIX and FreeBSD based open-source OS.
It was released by Apple in 2000. That's why the OS X analyzer is called darwin - Cuckoo's choice, not mine.

The process for the analyzer seems to be as follows:

1. Cuckoo checks the status of agent.py (running on the guest) until it comes up
2. Cuckoo sends a zipped file of analyzer/darwin/ to agent.py
3. The guest agent unzips the files to /ANALYZER_FOLDER/<random 5-10 characters>/
    (ANALYZER_FOLDER is the home folder of the user agent.py runs as)
4. Cuckoo sends the key/value pair options for the analysis.
5. The agent writes those options to analyzer.conf in the folder with the unzipped files
6. Cuckoo sends the file sample to the agent
7. The agent writes the file to /tmp
8. Cuckoo sends the execute commands
9. The agent executes analyzer.py
10. Cuckoo polls the agent until the analyzer has finished
11. The agent sends the results folder to Cuckoo
12. Cuckoo stores the results in storage/ on the host

Source: http://public.honeynet.org/pipermail/cuckoo/2013-June/001489.html
"""

import logging
import sys
import os
import os.path
import traceback
import xmlrpclib
import random
import hashlib
import socket
import time
import fnmatch
import fcntl
import termios
import array
import pkgutil
import subprocess
import psutil

from threading import Lock, Thread
from ctypes import create_unicode_buffer, create_string_buffer
from ctypes import c_wchar_p, byref, c_int, sizeof

''' These are Cuckoo files we are importing here '''
from lib.common.constants import PATHS, PIPE, SHUTDOWN_MUTEX #OS path constants
from lib.core.startup import create_folders, init_logging #creates results folders and configures logger
from lib.core.config import Config #parses the analysis.conf configuration file
from lib.common.results import upload_to_host
from lib.common.hashing import hash_file
from lib.api.process import Process
from lib.common.abstracts import Package, Auxiliary
from lib.core.packages import choose_package
from lib.common.exceptions import CuckooError, CuckooPackageError
from modules import auxiliary

#get logger
log = logging.getLogger()

FILES_LIST = [] #list of files to transfer to the Cuckoo host
DUMPED_LIST = [] #files already transferred to host
PROCESS_LIST = [] #list of watched processes, either started by us or by the sample

PROTECTED_LIST = ["sleep", "kernel_task"] #processes that are not traced

def add_pid(pid):
    """Add a process to process list."""
    if isinstance(pid, (int, long, str)):
        log.info("Added new process to list with pid: %s", pid)
        PROCESS_LIST.append(int(pid))

def add_pids(pids):
    """Add PID."""
    if isinstance(pids, (tuple, list)):
        for pid in pids:
            add_pid(pid)
    else:
        add_pid(pids)

def add_file(file_path):
    """Add a file to list of files to be copied to the host."""
    if file_path not in FILES_LIST:
        log.info("Added new file to list with path: %s",
                 unicode(file_path).encode("utf-8", "replace"))
        FILES_LIST.append(file_path)

def dump_file(file_path):
    """Create a copy of the given file path and send it to the host."""
    try:
        if os.path.exists(file_path):
            sha256 = hash_file(hashlib.sha256, file_path)
            if sha256 in DUMPED_LIST:
                # The file was already dumped
                # Cuckoo normally just skips the file, I have chosen not to
                #return
                log.warning("File at path \"%s\" has a hash that is a duplicate of another dumped file.",
                        file_path)
        else:
            log.warning("File at path \"%s\" does not exist, skip.",
                        file_path)
            return
    except IOError as e:
        log.warning("Unable to access file at path \"%s\": %s", file_path, e)
        return

    log.info("File path is %s and file size is %d.", file_path, os.stat(file_path).st_size)

    #choose the correct folder
    if "logs" in file_path:
        upload_path = os.path.join("logs", os.path.basename(file_path))
    elif "drop" in file_path:
        upload_path = os.path.join("files", os.path.basename(file_path))
    else:
        upload_path = os.path.join("files",
                               str(random.randint(100000000, 9999999999)),
                               os.path.basename(file_path))
    log.info("Upload path is %s.", upload_path)

    #send file to host
    try:
        upload_to_host(file_path, upload_path)
        DUMPED_LIST.append(sha256)
    except (IOError, socket.error) as e:
        log.error("Unable to upload dropped file at path \"%s\": %s",
                  file_path, e)

def dump_files():
    """Dump all the dropped files.
       This function transfers all the results files to the host."""
    for file_path in FILES_LIST:
        log.info("Dumping %s to host,", file_path)
        dump_file(file_path)

class PipeServer(Thread):
    """Cuckoo PIPE server.

    This Pipe Server receives notifications from the injected processes for
    new processes being spawned and for files being created or deleted.
    """

    def __init__(self, pipe_name=PIPE):
        """@param pipe_name: Cuckoo PIPE server name."""
        log.info("Starting PipeSever")
        Thread.__init__(self)
        self.pipe_name = pipe_name
        self.fd = -1
        self.do_run = True
        self.handlers = []
        self.created = False
        self.iocbuf = array.array('i', [0])
        self.h_pipe = None

    def stop(self):
        """Stop PIPE server."""
        start_time = time.time()
        end_time = start_time + 30
        #wait until we get everything...up to 30 seconds of extra time
        while self.get_content() > 0 and time.time() < end_time:
            if len(self.handlers) <= 20:
                handle = PipeHandler(self.h_pipe)
                handle.daemon = True
                handle.start()
                self.handlers.append(handle)
            log.info("Waiting to process all pipe data")
            time.sleep(0.5)
        self.do_run = False
        #delete the FIFO pipe
        os.unlink(self.pipe_name)

    def is_done(self):
        return not self.do_run

    def run(self):
        """Create and run PIPE server.
        @return: operation status.
        """
        try:
            if not self.created:
                # create the pipe
                os.mkfifo(self.pipe_name)
                self.created = True
                # If you use the normal open() function, it will block and no input will be received
                self.fd = os.open(self.pipe_name, os.O_NONBLOCK) #returns a file descriptor
                #wrap the file descriptor in a file object
                self.h_pipe = os.fdopen(self.fd, 'r')
                log.info("Opened pipe file %s with fd %d", self.pipe_name, self.fd)
        except:
            log.exception("Unable to start process communication pipe.")

        while self.do_run:
            # There is no way to poll for a connection to a named pipe on Unix
            # So we check the file size
            if self.get_content() > 0 and len(self.handlers) < 20:
                #log.info("Starting a pipe handler...")
                handle = PipeHandler(self.h_pipe)
                handle.daemon = True
                handle.start()
                self.handlers.append(handle)
            else:
                # Sleep for a bit
                time.sleep(0.05)

        return True

    def get_content(self):
        """
        Get the number of bytes in the pipe that can be read.
        @return: the number of bytes
        """
        try:
            fcntl.ioctl(self.fd, termios.FIONREAD, self.iocbuf, True)
        except:
            log.exception("Unable to read bytes from pipe.")
        return self.iocbuf[0]


class PipeHandler(Thread):
    """Pipe Handler.

    This class handles the notifications received through the Pipe Server and
    decides what to do with them.
    """

    F_LOGFILE = "file_activity.log"
    W_LOGFILE = "file_writes.log"
    C_LOGFILE = "file_creation.log"
    D_LOGFILE = "file_deletion.log"
    read_lock = Lock()

    def __init__(self, h_pipe):
        """@param h_pipe: PIPE to read."""
        Thread.__init__(self)
        self.h_pipe = h_pipe
        self.part = ''
        self.done = False

    def run(self):
        """Run handler.
        @return: operation status.
        """
        data = ""
        wait = False
        proc = None

        # Read the data submitted to the Pipe Server.
        while True:
            while True:
                try:
                    PipeHandler.read_lock.acquire()
                    data = self.h_pipe.readline()
                    PipeHandler.read_lock.release()
                    break
                except IOError:
                    log.error("Unable to open process communication pipe, retrying.")

            if data == '':
                break

            if data:
                #one line = one logging command
                c = [data]
                for command in c:

                    if not command.endswith('\n'): #if we have read a partial line
                        log.info("Saving a part of a log")
                        self.part = command #save it for later
                        continue

                    if self.part != '': # append any pieces to the end
                        log.info("Using a part of a log")
                        command = self.part + command
                        self.part = ''

                    if command.startswith("FILE_ACTIVITY:"):
                        self.writeToLogFile(os.path.join(PATHS["logs"], self.F_LOGFILE), command[14:len(command)])
                    elif command.startswith("FILE_CREATE:"):
                        self.writeToLogFile(os.path.join(PATHS["logs"], self.C_LOGFILE), command[12:len(command)])
                    elif command.startswith("FILE_DELETE:"):
                        self.writeToLogFile(os.path.join(PATHS["logs"], self.D_LOGFILE), command[12:len(command)])
                    elif command.startswith("FILE_WRITE:"):
                        self.writeToLogFile(os.path.join(PATHS["logs"], self.W_LOGFILE), command[11:len(command)])
                    elif command.startswith("PROCESS:"):
                        process_id = int(command[8:len(command)])
                        if process_id not in PROCESS_LIST:
                            if psutil.pid_exists(process_id):
                                h_p = psutil.Process(process_id)
                                proc = Process(pid=process_id, h_process=h_p, thread_id=None)
                                filename = proc.get_filepath()
                                log.info("Announced new process name: %s with pid %d", filename, process_id)
                                if not filename in PROTECTED_LIST:
                                    proc.start_trace()
                                add_pids(process_id)
                    elif command.startswith("EXEC:"):
                        log.info(command)
                    else:
                        log.error("Invalid pipe command: %s", command)
                    continue

            #break

        # We wait until the injected library reports back.
        if wait:
            proc.wait()

        if proc:
            proc.close()

        self.done = True
        return True

    def writeToLogFile(self, logfile, data):
        try:
            flog = open(logfile, 'a+')
            flog.write(data)
            flog.close()
        except:
            log.error("Unable to write to logfile %s.", logfile)

class Analyzer:
    """Cuckoo Darwin (OS X) Analyzer.
    """

    PIPE_SERVER_COUNT = 1

    def __init__(self):
        self.pipes = [None]*self.PIPE_SERVER_COUNT
        self.config = None
        self.target = None

    def complete(self):
        """Mark the analysis as completed and return files"""

        # Oh look, it's done
        log.info("Analysis completed")
        # Stop the Pipe Servers.
        for x in xrange(self.PIPE_SERVER_COUNT):
            self.pipes[x].stop()
            while not self.pipes[x].is_done():
                log.info("Waiting for Pipe Servers to finish")
                time.sleep(0.1)

        # pick up log files and created files from the system file call hooks
        # these are stored in ~/tmp/
        flog_root = os.path.join(os.getenv("HOME"), "tmp") #get the path
        if os.path.exists(flog_root):
            #transfer the log files to the "logs" directory - there could be 3 or there could be none
            for f in os.listdir(flog_root):
                if fnmatch.fnmatch(f, 'file_*.log'): #if the file is one of our log files
                    os.rename(os.path.join(flog_root, f), os.path.join(PATHS["logs"], f)) #then move it
                else: #all the other files in the directory will be files that were deleted
                    log.info("Adding file %s with size %d", os.path.join(flog_root, f), os.path.getsize(os.path.join(flog_root, f)))
                    os.rename(os.path.join(flog_root, f), os.path.join(PATHS["files"], f)) #move those to the files folder
            # copy over any created files that were not in the deleted files list
            if os.path.exists(os.path.join(PATHS["logs"], "file_creation.log")):
                #open the log file for reading - it will have one file path per line
                flog = open(os.path.join(PATHS["logs"], "file_creation.log"))
                for row in flog.readlines():
                    row = row.strip("\n")
                    # get rid of the timestamp in front
                    split = row.split(":")
                    row = split[len(split)-1].strip(" ")
                    log.info("Looking for %s - exists: %s", row, str(os.path.exists(row)))
                    #if the file has not already been copied, copy it over
                    if os.path.exists(row) and os.path.isfile(row) and not os.path.exists(os.path.join(PATHS["files"], os.path.basename(row))):
                        try:
                            log.info("Adding file %s with size %d", row, os.path.getsize(row))
                            os.rename(row, os.path.join(PATHS["files"], os.path.basename(row)))
                        except IOError:
                            log.error("Failed to extract created file %s.", row)

                flog.close()

        # Dump all the relevant files to the host
        for folder, subs, files in os.walk(PATHS["root"]):
            for filename in files:
                path = os.path.join(folder, filename)
                add_file(path)

        dump_files()


    def prepare(self):
        """
        Prepare the environment for analysis.
        """
        # Create the folders used for storing the results.
        create_folders()

        # Initialize logging.
        init_logging()

        # Parse the analysis configuration file generated by the agent.
        self.config = Config(cfg="analysis.conf")

        # Initialize and start the Pipe Servers. This is going to be used for
        # communicating with the injected and monitored processes.
        for x in xrange(self.PIPE_SERVER_COUNT):
            self.pipes[x] = PipeServer()
            self.pipes[x].daemon = True
            self.pipes[x].start()

        # We update the target according to its category. If it's a file, then
        # we store the path.
        if self.config.category == "file":
            #Note: The /tmp directory is specified in agent.py for linux and darwin
            self.target = os.path.join("/tmp",
                                       str(self.config.file_name))
        # If it's a URL, well.. we store the URL.
        else:
            self.target = self.config.target
        log.info("Target is at %s", self.target)

        # Execsnoop traces process creation using Dtrace
        pargs = ["execsnoop", "-a", "-e"]
        results = open(os.path.join(PATHS["logs"], "processes.log"), "a+")
        try:
            proc = subprocess.Popen(pargs, stdout=results, stderr=results)
            log.info("Starting Execsnoop")
        except (OSError, ValueError):
            log.exception("Failed to start execsnoop.")
        results.close()

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        #set up the analysis
        self.prepare()

        log.info("Starting analyzer from: %s", os.getcwd())
        log.info("Storing results at: %s", PATHS["root"])

        # If no analysis package was specified at submission, we try to select
        # one automatically.
        if not self.config.package:
            log.info("No analysis package specified, trying to detect "
                     "it automagically.")
            # If the analysis target is a file, we choose the package according
            # to the file format.
            if self.config.category == "file":
                package = choose_package(self.config.file_type, self.config.file_name)
            # If it's an URL, try to use Safari
            else:
                package = "safari"

            # If we weren't able to automatically determine the proper package,
            # we need to abort the analysis.
            if not package:
                raise CuckooError("No valid package available for file "
                                  "type: {0}".format(self.config.file_type))

            log.info("Automatically selected analysis package \"%s\"", package)
        # Otherwise just select the specified package.
        else:
            package = self.config.package

        # Generate the package path.
        package_name = "modules.packages.%s" % package

        # Try to import the analysis package.
        try:
            __import__(package_name, globals(), locals(), ["dummy"], -1)
        # If it fails, we need to abort the analysis.
        except ImportError:
            raise CuckooError("Unable to import package \"{0}\", does "
                              "not exist.".format(package_name))

        # Initialize the package parent abstract.
        Package()

        # Enumerate the abstract's subclasses.
        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class "
                              "(package={0}): {1}".format(package_name, e))

                # Initialize the analysis package.
        pack = package_class(self.get_options())

        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliary.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            if ispkg:
                continue

            # Import the auxiliary module.
            try:
                __import__(name, globals(), locals(), ["dummy"], -1)
            except ImportError as e:
                log.warning("Unable to import the auxiliary module "
                            "\"%s\": %s", name, e)

        # Walk through the available auxiliary modules.
        aux_enabled, aux_avail = [], []
        for module in Auxiliary.__subclasses__():
            # Try to start the auxiliary module.
            try:
                aux = module()
                aux_avail.append(aux)
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented",
                            aux.__class__.__name__)
                continue
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s",
                            aux.__class__.__name__, e)
                continue
            finally:
                log.info("Started auxiliary module %s",
                         aux.__class__.__name__)
                aux_enabled.append(aux)

        # Initialize the analysis package.
        pack = package_class(self.get_options())

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        try:
            pids = pack.start(self.target)
        except NotImplementedError:
            raise CuckooError("The package \"{0}\" doesn't contain a run "
                              "function.".format(package_name))
        except CuckooPackageError as e:
            raise CuckooError("The package \"{0}\" start function raised an "
                              "error: {1}".format(package_name, e))
        except Exception as e:
            raise CuckooError("The package \"{0}\" start function encountered "
                              "an unhandled exception: "
                              "{1}".format(package_name, e))

        # If the analysis package returned a list of process IDs, we add them
        # to the list of monitored processes and enable the process monitor.
        if pids:
            add_pids(pids)
            pid_check = True

        # If the package didn't return any process ID (for example in the case
        # where the package isn't enabling any behavioral analysis), we don't
        # enable the process monitor.
        else:
            log.info("No process IDs returned by the package, running "
                     "for the full timeout")
            pid_check = False


        time_counter = 0

        while True:
            time_counter += 1
            if time_counter == int(self.config.timeout):
                log.info("Analysis timeout hit, terminating analysis")
                break

            try:
                # If the process monitor is enabled we start checking whether
                # the monitored processes are still alive.
                if pid_check:
                    for pid in PROCESS_LIST:
                        if not Process(pid=pid).is_alive():
                            log.info("Process with pid %s has terminated", pid)
                            PROCESS_LIST.remove(pid)

                    # If none of the monitored processes are still alive, we
                    # can terminate the analysis.
                    if not PROCESS_LIST:
                        log.info("Process list is empty, "
                                 "terminating analysis.")
                        break

                    # Update the list of monitored processes available to the
                    # analysis package. It could be used for internal
                    # operations within the module.
                    pack.set_pids(PROCESS_LIST)

                try:
                    # The analysis packages are provided with a function that
                    # is executed at every loop's iteration. If such function
                    # returns False, it means that it requested the analysis
                    # to be terminate.
                    if not pack.check():
                        log.info("The analysis package requested the "
                                 "termination of the analysis...")
                        break

                # If the check() function of the package raised some exception
                # we don't care, we can still proceed with the analysis but we
                # throw a warning.
                except Exception as e:
                    log.warning("The package \"%s\" check function raised "
                                "an exception: %s", package_name, e)
            finally:
                # Sleep for one second
                time.sleep(1)

        try:
            # Before shutting down the analysis, the package can perform some
            # final operations through the finish() function.
            pack.finish()
        except Exception as e:
            log.warning("The package \"%s\" finish function raised an "
                        "exception: %s", package_name, e)

        # Try to terminate remaining active processes. We do this to make sure
        # that we clean up remaining open handles (sockets, files, etc.).
        log.info("Terminating remaining processes before shutdown...")

        for pid in PROCESS_LIST:
            proc = Process(pid=pid)
            if proc.is_alive():
                try:
                    proc.terminate()
                except:
                    continue


        # Call the completion procedure
        self.complete()

        return True

    def get_options(self):
        """Get analysis options.
        @return: options dict.
        """
        # The analysis package can be provided with some options in the
        # following format:
        #   option1=value1,option2=value2,option3=value3
        #
        # Here we parse such options and provide a dictionary that will be made
        # accessible to the analysis package.
        options = {}
        if self.config.options:
            try:
                # Split the options by comma.
                fields = self.config.options.strip().split(",")
            except ValueError as e:
                log.warning("Failed parsing the options: %s", e)
            else:
                for field in fields:
                    # Split the name and the value of the option.
                    try:
                        key, value = field.strip().split("=")
                    except ValueError as e:
                        log.warning("Failed parsing option (%s): %s", field, e)
                    else:
                        # If the parsing went good, we add the option to the
                        # dictionary.
                        options[key.strip()] = value.strip()

        return options

#executed when this file is run
if __name__ == "__main__":
    success = False #did the analyzer successfully run?
    error = "" #any error messages the analyzer returns

    try:
        # Initialize the main analyzer class.
        analyzer = Analyzer()

        # Run it and wait for the response.
        success = analyzer.run()

    # This is not likely to happen.
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"

    # If the analysis process encountered a critical error, it will raise a
    # CuckooError exception, which will force the termination of the analysis.
    # Notify the agent of the failure. Also catches unexpected exceptions.
    except Exception as e:
        # Store the error.
        error_exc = traceback.format_exc()
        error = str(e)

        # Just to be paranoid.
        if len(log.handlers) > 0:
            log.exception(error_exc)
        else:
            sys.stderr.write("{0}\n".format(error_exc))

    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        # Establish connection with the agent XMLRPC server.
        server = xmlrpclib.Server("http://127.0.0.1:8000", allow_none=True)
        logging.critical("success: %s, error: %s, PATHS[root]: %s" % (success, error, PATHS["root"]))
        server.complete(success, error, PATHS["root"])