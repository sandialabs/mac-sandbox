from lib.common.abstracts import Package
import os
import os.path
import plistlib
import logging
import subprocess

from AppKit import *
import Foundation
from PyObjCTools import AppHelper

#get logger
log = logging.getLogger()

class OpenFile(NSObject):

    def setPath(self, p, test):
        self.path = p
        self.loop = test

    def run_(self, event):
        if str(event.userInfo()["NSApplicationName"]) == "TextEdit":
            #open the file in question
            subprocess.call(["/usr/bin/open", "-e", self.path])
            #remove the event observer
            ws = NSWorkspace.sharedWorkspace()
            nc = ws.notificationCenter()
            nc.removeObserver_name_object_(self, NSWorkspaceDidLaunchApplicationNotification, None)
            self.loop.stop()

class RTF(Package):
    """ Plist and RTF analysis package
    """

    def stop(self):
        self.is_open = True

    def start(self, path):
        textedit = self.getAppFilePath("/Applications/TextEdit.app/")

        #fix what permissions issues we can
        os.chmod(path, 0o777)
        result = subprocess.call(["xattr", "-c", path])

        # The remaining problem is that we can't fight Apple's sandbox - it will refuse to
        # open the document in a nice scripted fashion unless it has already been opened
        # once by a signed piece of software or the user
        # In this case, 'open' is the signed software of choice

        #create the observer watching for application launch events
        ws = NSWorkspace.sharedWorkspace()
        nc = ws.notificationCenter()
        op = OpenFile.new()
        op.setPath(path, self)
        nc.addObserver_selector_name_object_(op, 'run:', NSWorkspaceDidLaunchApplicationNotification, None)
        #start the Preview process
        pid = self.execute(textedit, (textedit,))

        #Wait until the process is open
        self.is_open = False
        runLoop = NSRunLoop.currentRunLoop()
        date = NSDate.dateWithTimeIntervalSinceNow_(1.0)
        while not self.is_open:
            date = NSDate.dateWithTimeIntervalSinceNow_(1.0)
            NSRunLoop.runUntilDate_(runLoop, date)

        #return the pid of TextEdit
        return pid

        #Old, less reliable bash method
        #args = "\"" + textedit + "\" & sleep 2 && open -a \"TextEdit\" \""+path+"\""
        #return self.execute(bash, (bash, "-c",  "%s" % args))

        #This is the simple method you could do if TextEdit weren't sandboxed
        #return self.execute(textedit, (textedit, path))