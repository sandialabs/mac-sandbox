

import os
import os.path
import plistlib
import subprocess
import logging
import time

from AppKit import *
import Foundation
from PyObjCTools import AppHelper

from lib.common.abstracts import Package

#get logger
log = logging.getLogger()

class OpenPDF(NSObject):

    def setPath(self, p, test):
        self.path = p
        self.loop = test

    def run_(self, event):
        if str(event.userInfo()["NSApplicationName"]) == "Preview":
            #open the file in question
            subprocess.call(["/usr/bin/open", "-a", "Preview", self.path])
            #remove the event observer
            ws = NSWorkspace.sharedWorkspace()
            nc = ws.notificationCenter()
            nc.removeObserver_name_object_(self, NSWorkspaceDidLaunchApplicationNotification, None)
            self.loop.stop()


class PDF(Package):
    """PDF analysis package."""

    def stop(self):
        self.is_open = True

    def start(self, path):
        #Use Preview, the default PDF application
        app = self.getAppFilePath("/Applications/Preview.app")

        #A lot of downloaded PDFs will contain a "quarantine" attribute until opened for the first time
        # This will cause a permission issue unless we remove it
        # But there are still other permission issues with downloaded files, apparently
        os.chmod(path, 0o777)
        result = subprocess.call(["xattr", "-c", path])

        # The remaining problem is that we can't fight Apple's sandbox - it will refuse to
        # open the document in a nice scripted fashion unless it has already been opened
        # once by a signed piece of software or the user
        # In this case, 'open' is the signed software of choice

        #create the observer watching for application launch events
        ws = NSWorkspace.sharedWorkspace()
        nc = ws.notificationCenter()
        op = OpenPDF.new()
        op.setPath(path, self)
        nc.addObserver_selector_name_object_(op, 'run:', NSWorkspaceDidLaunchApplicationNotification, None)
        #start the Preview process
        pid = self.execute(app, (app,))

        #Wait until the process is open
        self.is_open = False
        runLoop = NSRunLoop.currentRunLoop()
        date = NSDate.dateWithTimeIntervalSinceNow_(1.0)
        while not self.is_open:
            date = NSDate.dateWithTimeIntervalSinceNow_(1.0)
            NSRunLoop.runUntilDate_(runLoop, date)

        #return the pid of Preview
        return pid

        #This is the simple method you could do if Preview weren't sandboxed
        #return self.execute(app, (app, path))

        #Another alternate, unreliable method using bash and sleep
        #args = "\"" + app + "\" & sleep 5  && open -a Preview "+path
        #return self.execute(bash, (bash, "-c",  "%s" % args))

