
import os
import os.path
import stat
import logging
import plistlib
from zipfile import ZipFile, BadZipfile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

#get logger
log = logging.getLogger()

class Zip(Package):
    """Zip analysis package."""

    def start(self, path):
        root = os.environ["TMPDIR"]
        password = self.options.get("password")

        with ZipFile(path, "r") as archive:
            zipinfos = archive.infolist()
            try:
                archive.extractall(path=root, pwd=password)
            except BadZipfile as e:
                raise CuckooPackageError("Invalid Zip file")
            except RuntimeError:
                try:
                    archive.extractall(path=root, pwd="infected")
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Zip file: "
                                             "{0}".format(e))

        file_name = self.options.get("file")
        # If no file name is provided via option, take the first file.
        if not file_name:
            # No name provided try to find a better name.
            if len(zipinfos):
                # Take the first one.
                file_name = zipinfos[0].filename
            else:
                raise CuckooPackageError("Empty ZIP archive")

        file_path = os.path.join(root, file_name)
        #Have to make the file(s) executable
        os.chmod(file_path, 0o777 | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if os.path.isdir(file_path):
            for root, dirs, files in os.walk(file_path):
                for d in files:
                    os.chmod(os.path.join(root, d), 0o777 | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        #Handle .app files separately
        if file_name.endswith(".app") or file_name.endswith(".app/"):
            (exec_path, fpath) = self.getAppFilePath(file_path)
            args = self.options.get("arguments")
            if args is None:
                return self.execute(exec_path, (exec_path, "%s" % fpath))
            return self.execute(exec_path, (exec_path, "%s %s" % (fpath, args)))

        return self.execute(file_path, (file_path, self.options.get("arguments")))

    def getAppFilePath(self, file_path):
        # the reason we don't just do "open file.app" is because OS X has restrictions on open that make it hard to trace
        open = "/usr/bin/open"

        #find Info.plist
        plist = ""
        path = self.findFile(file_path, "Info.plist")
        for root, dirs, files in os.walk(file_path):
            for f in files:
                if f == "Info.plist":
                    #read the plist file
                    plist = plistlib.readPlist(os.path.join(root, f))
                    break

        if path == "":  #no Info.plist found, this is an illegally structured app
            log.info("No Info.plist found within .app file")
            return (open, file_path)
        else:
            plist = plistlib.readPlist(path)

        try:
            #get the name of the main executable of this app
            exec_file = plist["CFBundleExecutable"]
        except KeyError: #no executable was listed, this is an illegally structured app
            log.info("No main executable name found in Info.plist")
            return (open, file_path)

        #get the full path of the executable
        exec_path = self.findFile(file_path, exec_file)
        return (exec_path, "")


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

