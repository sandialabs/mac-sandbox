"""
Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
this work by or on behalf of the U.S. Government. 
NOTICE:
For five (5) years from  the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, and perform publicly and display publicly, by or on behalf of the Government. There is provision for the possible extension of the term of this license. Subsequent to that period or any extension granted, the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, distribute copies to the public, perform publicly and display publicly, and to permit others to do so. The specific term of the license can be identified by inquiry made to Sandia Corporation or DOE.
NEITHER THE UNITED STATES GOVERNMENT, NOR THE UNITED STATES DEPARTMENT OF ENERGY, NOR SANDIA CORPORATION, NOR ANY OF THEIR EMPLOYEES, MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LEGAL RESPONSIBILITY FOR THE ACCURACY, COMPLETENESS, OR USEFULNESS OF ANY INFORMATION, APPARATUS, PRODUCT, OR PROCESS DISCLOSED, OR REPRESENTS THAT ITS USE WOULD NOT INFRINGE PRIVATELY OWNED RIGHTS.
Any licensee of this software has the obligation and responsibility to abide by the applicable export control laws, regulations, and general prohibitions relating to the export of technical data. Failure to obtain an export control license or other authority from the Government may result in criminal liability under U.S. laws.

The purpose of this module is simply to pull data from the logs of the darwin analyzer into a format that
the signature and JSON module can use (aka a giant structure of dictionaries and lists).
The existing behavior module only works for the Windows analyzer results.
This module pulls data from the file activity logs, the processes log, and the api call logs.
"""

import os
import os.path

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

class BehaviorOSX(Processing):
    """Pull results from log files"""

    def run(self):
        """Run extract of printable strings.
        @return: list of printable strings.
        """
        self.key = "behavior_osx"

        result = {} #dictionary of call lists to return
        result["api_calls"] = {}

        #loop through to find the files of interest
        for root, dirs, files in os.walk(self.logs_path):
            for f in files:
                if "api_calls" in f: #api calls go in a dictionary of lists
                    name = os.path.join(root, f)
                    result["api_calls"][os.path.splitext(f)[0]] = self.readFile(name)
                elif "processes" in f: #processes are just a list
                    name = os.path.join(root, f)
                    result["processes"] = self.readFile(name)
                elif "file_" in f: #there are 4 logs related to file activity
                    name = os.path.join(root, f)
                    result[os.path.splitext(f)[0]] = self.readFile(name, skip=False)

        return result

    def readFile(self, fname, skip=True):
        """
        Turns a newline-separated file into a list
        :param skip: When true, this means you skip the first line of the file as headers
        :param fname: The name of the file to process
        :return: a list of the file info
        """

        results = [] # the list of lines in the file

        f = open(fname, "r")

        if skip: #skip the first line of the file
            f.readline()

        line = f.readline()
        while line is not None and line != "":
            results.append(line)
            line = f.readline()

        f.close()

        return results


