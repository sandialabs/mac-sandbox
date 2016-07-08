"""
Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
this work by or on behalf of the U.S. Government. 
NOTICE:
For five (5) years from  the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, and perform publicly and display publicly, by or on behalf of the Government. There is provision for the possible extension of the term of this license. Subsequent to that period or any extension granted, the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, distribute copies to the public, perform publicly and display publicly, and to permit others to do so. The specific term of the license can be identified by inquiry made to Sandia Corporation or DOE.
NEITHER THE UNITED STATES GOVERNMENT, NOR THE UNITED STATES DEPARTMENT OF ENERGY, NOR SANDIA CORPORATION, NOR ANY OF THEIR EMPLOYEES, MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LEGAL RESPONSIBILITY FOR THE ACCURACY, COMPLETENESS, OR USEFULNESS OF ANY INFORMATION, APPARATUS, PRODUCT, OR PROCESS DISCLOSED, OR REPRESENTS THAT ITS USE WOULD NOT INFRINGE PRIVATELY OWNED RIGHTS.
Any licensee of this software has the obligation and responsibility to abide by the applicable export control laws, regulations, and general prohibitions relating to the export of technical data. Failure to obtain an export control license or other authority from the Government may result in criminal liability under U.S. laws.
"""

import os
import os.path

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

filters = ["FILE_ACTIVITY:", "FILE_CREATE:", "FILE_DELETE:", "FILE_WRITE:", "PROCESS:"]

class FilterSyscall(Processing):
    """Filter out syscalls caused by system call hooks."""

    def filterLine(self, line):
        for f in filters:
            if f in line:
                return True
        return False

    def filterFile(self, fname):
        data = open(fname, 'r')
        output = []

        #take out the 4 commands that make up the pipe write
        i = 0
        line = data.readline()
        while line != '' and not line is None:
            if self.filterLine(line):
                if i > 2:
                    del output[-1]
                    del output[-1]
                line = data.readline()
                i += 1
            else:
                output.append(line)
            line = data.readline()
            i += 1


        #close the source file
        data.close()
        #delete the source file
        os.remove(fname)
        #rewrite the system call log
        out = open(fname, 'w+')
        for line in output:
            out.write(line)
        out.close()

        return output


    def run(self):
        """Filter and extract syscall logs
        @return: dictionary of list of syscalls.
        """
        self.key = "filter_syscall"
        call_logs = [] #list of all the syscall file logs
        result = {} #dictionary of call lists to return

        #find all the syscall logs, if any
        for root, dirs, files in os.walk(self.logs_path):
            for f in files:
                if "system_calls" in f:
                    call_logs.append(os.path.join(root, f))

        #for each file, look for calls caused by the hook library
        for c in call_logs:
            result[c] = self.filterFile(c)

        return result
