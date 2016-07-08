

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

class OpenDoc(NSObject):

    def setPath(self, p, test, app):
        self.path = p
        self.loop = test
        self.app = app

    def run_(self, event):
        if "Word" in str(event.userInfo()["NSApplicationName"]):
            #open the file in question
            subprocess.call(["/usr/bin/open", "-a", self.app, self.path])
            #remove the event observer
            ws = NSWorkspace.sharedWorkspace()
            nc = ws.notificationCenter()
            nc.removeObserver_name_object_(self, NSWorkspaceDidLaunchApplicationNotification, None)
            self.loop.stop()

class Doc(Package):
    """Word analysis package.
    Note that this tends to be a bit picky - if the document is too old for the version of Word
    on the VM, it may not open properly"""

    def stop(self):
        self.is_open = True

    def start(self, path):
        (word, app) = self.get_path("Microsoft Office")

        # There is no nice programmatic way to open a file in Word on OS X (other than open -a)
        # There is on Windows, not here. No command line arguments to work with at all
        #create the observer watching for application launch events
        ws = NSWorkspace.sharedWorkspace()
        nc = ws.notificationCenter()
        op = OpenDoc.new()
        op.setPath(path, self, app)
        nc.addObserver_selector_name_object_(op, 'run:', NSWorkspaceDidLaunchApplicationNotification, None)
        #start the Preview process
        pid = self.execute(word, (word,))

        #Wait until the process is open
        self.is_open = False
        runLoop = NSRunLoop.currentRunLoop()
        date = NSDate.dateWithTimeIntervalSinceNow_(1.0)
        while not self.is_open:
            date = NSDate.dateWithTimeIntervalSinceNow_(1.0)
            NSRunLoop.runUntilDate_(runLoop, date)

        #return the pid of Word
        return pid

        #Old, less reliable bash method
        #args = "\"" + word + "\" & sleep 5 && echo \'tell application \""+app+"\" to open \""+path+"\"\' | /usr/bin/osascript"
        #return self.execute(bash, (bash, "-c",  "%s" % args))

    def get_path(self, name):
        #attempt to find Microsoft Word
        word_dir = ""
        dir = self.findDir("/Applications/", name)
        word_dir = os.path.join(dir, "Microsoft Word.app")

        if word_dir != "":
            return (self.getAppFilePath(word_dir), "Microsoft Word")

        #If we can't find Word, try to find Pages
        word_dir = self.findDir("/Applications/", "Pages")

        if word_dir != "":
            return (self.getAppFilePath(word_dir), "Pages")

        #If no Pages, open the darn thing in TextEdit
        return (self.getAppFilePath("/Applications/TextEdit.app/"), "TextEdit")

    def getAppFilePath(self, file_path):
        # the reason we don't just do "open file.app" is because OS X has restrictions on open that make it hard to trace
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

    def findDir(self, path, name):
        result = ""
        for root, dirs, files in os.walk(path):
            for d in dirs:
                if name in d:
                    return os.path.join(root, d)
        return result

    def findFile(self, path, name):
        result = ""
        for root, dirs, files in os.walk(path):
            for f in files:
                if name in f:
                    return os.path.join(root, f)
        return result

