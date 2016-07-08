
import os
import os.path
import plistlib
import logging
import subprocess

from AppKit import *
import Foundation
from PyObjCTools import AppHelper

from lib.common.abstracts import Package

#get logger
log = logging.getLogger()

class OpenURL(NSObject):

    def setPath(self, p, test):
        self.path = p
        self.loop = test

    def run_(self, event):
        if str(event.userInfo()["NSApplicationName"]) == "Safari":
            #open the file in question
            subprocess.call(["/usr/bin/open", "-a", "Safari", self.path])
            #remove the event observer
            ws = NSWorkspace.sharedWorkspace()
            nc = ws.notificationCenter()
            nc.removeObserver_name_object_(self, NSWorkspaceDidLaunchApplicationNotification, None)
            self.loop.stop()

class Safari(Package):
    """Safari analysis package."""

    def stop(self):
        self.is_open = True

    def start(self, url):
        safari = self.getAppFilePath("/Applications/Safari.app")

        #if we try and open the URL directly with "<safari> <url>", Safari treats it as a file path and tries to find it on the local machine
        #Create an observer to watch for Safari opening
        ws = NSWorkspace.sharedWorkspace()
        nc = ws.notificationCenter()
        op = OpenURL.new()
        op.setPath(url, self)
        nc.addObserver_selector_name_object_(op, 'run:', NSWorkspaceDidLaunchApplicationNotification, None)
        #start Safari
        pid = self.execute(safari, (safari,))

        #Wait until the process is open
        self.is_open = False
        runLoop = NSRunLoop.currentRunLoop()
        date = NSDate.dateWithTimeIntervalSinceNow_(1.0)
        while not self.is_open:
            date = NSDate.dateWithTimeIntervalSinceNow_(1.0)
            NSRunLoop.runUntilDate_(runLoop, date)

        #return the pid of Safari
        return pid

        #Old, less reliable bash method
        #args = "\"" + safari + "\" & sleep 5 && open -a Safari \""+url+"\"" #went with open because the AppleScript was unreliable
        #return self.execute(bash, (bash, "-c",  "%s" % args))
