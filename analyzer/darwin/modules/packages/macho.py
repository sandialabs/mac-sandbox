"""
This runs Mach-O executables and FAT files, provided they are the correct architecture for the VM in use.
"""

from lib.common.abstracts import Package

class MachO(Package):

    def start(self, path):
        args = self.options.get("arguments")
        if args:
            return self.execute(path, args)
        return self.execute(path, (path,))
