
import logging
import os.path

from lib.common.abstracts import Package

#get logger
log = logging.getLogger()

class Jar(Package):
    """Java analysis package."""

    def start(self, path):
        #this is the standard path, actually a symlink to the read Java files
        java = "/usr/bin/java"
        #make sure there is Java on this system
        if not os.path.isfile(java):
            log.error("Cannot run jar file: No Java installed on the guest system!")
            return None

        class_path = self.options.get("class")

        if class_path:
            return self.execute(java, (java, "-cp", path, class_path))
            #args = "-cp \"%s\" %s" % (path, class_path)
        else:
            return self.execute(java, (java, "-jar", path))
            #args = "-jar \"%s\"" % path
