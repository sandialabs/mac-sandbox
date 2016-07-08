

import logging
import os

from lib.common.abstracts import Package

#get logger
log = logging.getLogger()

class Python(Package):
    """Python analysis package."""

    def start(self, path):
        python = "/usr/bin/python" #symlink to actual python, default location for OS X
        #make sure there is Python here
        if not os.path.isfile(python):
            log.error("Cannot run python file: Python not found in /usr/bin")
            return None

        args = self.options.get("arguments", "")

        if args:
            return self.execute(python, (python, path, args))
        return self.execute(python, (python, path))
