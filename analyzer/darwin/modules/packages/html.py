

import shutil
import logging
import os
import os.path
import plistlib

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class HTML(Package):
    """HTML file analysis package."""

    def start(self, path):
        safari = self.getAppFilePath("/Applications/Safari.app")

        # Travelling inside malware universe you should bring a towel with you.
        # If a file detected as HTML is submitted without a proper extension,
        # or without an extension at all (are you used to name samples with hash?),
        # it might be opened as a text file, so your precious sample will not
        # be executed.
        # We help you sample to execute renaming it with a proper extension.
        if not path.endswith((".htm", ".html")):
            shutil.copy(path, path + ".html")
            path += ".html"
            log.info("Submitted file is missing extension, adding .html")

        return self.execute(safari, (safari, path))


