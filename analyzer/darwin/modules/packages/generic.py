"""
This is the package of last resort - Apple's "open" utility is very good
at determining what to use to open a file. Unfortunately, we cnanot get the pid
of the new process from ope, which means the sandbox will probably prematurely quit once
the open process is finished.
"""

from lib.common.abstracts import Package

class Generic(Package):
    """Generic analysis package."""

    def start(self, path):
        open = "/usr/bin/open"

        return self.execute(open, (open, path))
