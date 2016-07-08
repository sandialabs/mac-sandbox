"""
Extremely bare-bones copy of the Cuckoo Package-Process structure.
I have converted what I could for OS X and scrapped the rest.
"""

import os
import os.path
import plistlib
import logging

from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

#get logger
log = logging.getLogger()

class Package(object):
    """Base abstact analysis package."""
    PATHS = []

    def __init__(self, options={}):
        """@param options: options dict."""
        self.options = options
        self.pids = []

    def set_pids(self, pids):
        """Update list of monitored PIDs in the package context.
        @param pids: list of pids.
        """
        self.pids = pids

    def start(self):
        """Run analysis packege.
        @param path: sample path.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def check(self):
        """Check."""
        return True

    def _enum_paths(self):
        raise NotImplementedError

    def get_path(self, application):
        raise NotImplementedError

    def execute(self, path, args):

        p = Process()
        if not p.execute(path=path, args=args, suspended=True):
            raise CuckooPackageError("Unable to execute the initial process, "
                                     "analysis aborted.")
        return p.pid

    def finish(self):
        """Finish run.
        If specified to do so, this method dumps the memory of
        all running processes.
        """
        return True

    def getAppFilePath(self, file_path):
        # the reason we don't just do "open file" is because OS X has restrictions on open that make it hard to trace
        # and you can't get the started process' pid from it
        open = "/usr/bin/open"

        #find Info.plist
        plist = ""
        path = self.findFile(file_path, "Info.plist")

        if path == "":  #no Info.plist found, this is an illegally structured app
            log.info("No Info.plist found within .app file")
            return open
        else:
            plist = plistlib.readPlist(path)

        try:
            #get the name of the main executable of this app
            exec_file = plist["CFBundleExecutable"]
        except KeyError: #no executable was listed, this is an illegally structured app
            log.info("No main executable name found in Info.plist")
            return open

        #get the full path of the executable
        return self.findFile(file_path, exec_file)

    def findFile(self, path, name):
        result = ""
        for root, dirs, files in os.walk(path):
            for f in files:
                if name in f:
                    return os.path.join(root, f)
        return result

    def findDir(self, path, name):
        result = ""
        for root, dirs, files in os.walk(path):
            for d in dirs:
                if name in d:
                    return os.path.join(root, d)
        return result


class Auxiliary(object):
    pass


