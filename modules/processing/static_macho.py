"""
Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
this work by or on behalf of the U.S. Government. 
NOTICE:
For five (5) years from  the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, and perform publicly and display publicly, by or on behalf of the Government. There is provision for the possible extension of the term of this license. Subsequent to that period or any extension granted, the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, distribute copies to the public, perform publicly and display publicly, and to permit others to do so. The specific term of the license can be identified by inquiry made to Sandia Corporation or DOE.
NEITHER THE UNITED STATES GOVERNMENT, NOR THE UNITED STATES DEPARTMENT OF ENERGY, NOR SANDIA CORPORATION, NOR ANY OF THEIR EMPLOYEES, MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LEGAL RESPONSIBILITY FOR THE ACCURACY, COMPLETENESS, OR USEFULNESS OF ANY INFORMATION, APPARATUS, PRODUCT, OR PROCESS DISCLOSED, OR REPRESENTS THAT ITS USE WOULD NOT INFRINGE PRIVATELY OWNED RIGHTS.
Any licensee of this software has the obligation and responsibility to abide by the applicable export control laws, regulations, and general prohibitions relating to the export of technical data. Failure to obtain an export control license or other authority from the Government may result in criminal liability under U.S. laws.

This script extracts the metadata, imports, and whatever else we can get statically from Mach-O and FAT files.

# Depends on python-magic (and libmagic) and macholib
# Macholib: https://pypi.python.org/pypi/macholib/
# Python-magic: https://github.com/ahupp/python-magic
# Libmagic Instructions: http://www.brambraakman.com/blog/comments/installing_libmagic_in_mac_os_x_for_python-magic/

"""

import struct
from zipfile import ZipFile, BadZipfile
import os
import os.path
import plistlib
import logging
import shutil
import subprocess

#the magic library is used to identify the file type, since we can only handle certain kinds
try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False
# The macholib library is used to handle the byte-parsing of a lot of the file structures
try:
    #import the parsing stuff from the macholib library
    from macholib.MachO import MachO
    #import the header constants
    from macholib.mach_o import *
    HAVE_MACHO = True
except ImportError:
    HAVE_MACHO = False

'''Cuckoo libraries'''
from lib.cuckoo.common.abstracts import Processing #the framework for all processing modules
from lib.cuckoo.common.exceptions import CuckooProcessingError #error to throw if something goes wrong
import modules.processing.macho_data as data #custom library of human-readable field conversions

#get logger
log = logging.getLogger()


class MachO_Parse:
    """Mach-O and FAT file static analysis"""

    def __init__(self, file_path):
         ### Class Variables ###
        self.file_name = file_path #a single file to parse

    def parse(self):
        """Parse the file's static attributes.
        @return: analysis results dict or None.
        """
        results = {}

        # get the signature info via the codesign utility
        args = ["codesign","-dvvvv", self.file_name]
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error_output = proc.communicate()
        if proc.returncode: #error, probably file not signed
            results["signature"] = error_output
        else:
            results["signature"] = output

        #get the file object
        file_object = open(self.file_name, 'rb')


        #Use the macho library to parse out some structures
        pFile = MachO(self.file_name)

        #if this is a fat file, it will have multiple Mach-O objects inside it
        results["FAT_header"] = self.parseFATHeader(file_object, pFile)

        #parse all the Mach-O headers
        i = 1
        for h in pFile.headers:
            results["MachO_header" + str(i)] = self.parseMachOHeader(h, file_object)
            i +=1

        #close the file
        file_object.close()

        #return the dict of results
        return results

    def parseMachOHeader(self, header, file_object):
        results = {}
        m = header.MH_MAGIC
        #get down to the actual header info
        h = header.header

        ### get human-readable strings ###
        cpu_type = CPU_TYPE_NAMES.get(h.cputype, h.cputype)
        results["cpu_type"] = cpu_type
        #this needs a mask due to a couple high-bit types like lib64
        hex_stype = (h.cpusubtype + (1 << 32)) % (1 << 32)  #because some numbers turn out negative when read
        cpu_stype = self.getCPUSubtype(cpu_type, hex_stype & ~0xff000000)
        #test for the high-bit ones
        try:
            s = self.getCPUSubtype('high', hex_stype & 0xff000000)
            cpu_stype += ", " + s
        except TypeError: #meaning no matches
            pass
        results["cpu_subtype"] = cpu_stype
        #get the file type - library, executable, etc.
        results["ftype"] = data.FILE_TYPE.get(int(h.filetype))
        #get the list of flags
        results["flags"] = self.getFlags(h.flags)


        #reserved field only exists in 64-bit headers, so set to None if 32-bit
        res = 'NULL'
        if hasattr(h, 'reserved'):
            res = h.reserved
        results["reserved"] = res

        #parse the load commands
        (results["load_commands"], results["sections"]) = self.parseLoadCommands(header.commands)

        #get a stand-alone list of the dynamically linked libraries, just for convenience
        libs = []
        for lib in header.walkRelocatables():
            libs.append(lib[2])
        results["DyLinkedLibs"] = libs

        #get the imports/exports from the symbol table
        sym_cmd = header.getSymbolTableCommand() #get the symbol table load command from the header
        dyn_cmd = header.getDynamicSymbolTableCommand() #get the dynamic symbol table load command from the header
        (results["DefExtSymbols"], results["UndefExtSymbols"]) = self.parseSymbolTable(sym_cmd, dyn_cmd, file_object, header)


        return results

    def parseLoadCommands(self, commands):
        results = [] #list of all load commands to return
        sections = []

        # Each command is a tuple with 3 entries
        i = 0
        for cmd in commands: #list of load commands for one MachO header
            c = {}
            #the first entry is a load_command structure, made up of the command type and its size
            #get the human-readable command name
            cmd_name = data.LOAD_CMDS.get(cmd[0].cmd)
            #test for the high-bit LC_REQ_DYLD
            if cmd_name is None:
                s1 = data.LOAD_CMDS.get(cmd[0].cmd & 0xff000000) #check the high bit separately
                cmd_name = s1
                s2 = data.LOAD_CMDS.get(cmd[0].cmd & 0x00ffffff) #check the low bits
                cmd_name += ", " + s2
            c["cmd_name"] = cmd_name
            c["cmd_size"] = int(cmd[0].cmdsize)

            #the second entry in the tuple is the actual content of the command, which varies depending on the command
            # Since we can't predict the content without an excessively long switch statement, we just pull out
            # the structure attributes directly as a dict. It's not elegant but it works.
            c["cmd_content"] = cmd[1].__dict__["_objects_"]

            #sometimes some of the dict objects will create JSON errors
            for key in c["cmd_content"]:
                if isinstance(c["cmd_content"][key], str): #these strings are ASCII, and sometimes they don't play well with UTF-8
                    c["cmd_content"][key] = c["cmd_content"][key].decode('utf-8', 'ignore').strip('\u0000')
                if isinstance(c["cmd_content"][key], mach_version_helper): #these are Python objects JSON can't handle
                    c["cmd_content"][key] = c["cmd_content"][key].__dict__["_objects_"]


            # the third thing in the tuple is a string used by the command (usually a library/framework name)
            if "LC_SEGMENT" in c["cmd_name"]: #unless its a segment, then the sections need to be parsed
                #get human-readable memory flags for the segment
                c["cmd_content"]["maxprot"] = self.getMemProt(c["cmd_content"]["maxprot"])
                c["cmd_content"]["initprot"] = self.getMemProt(c["cmd_content"]["initprot"])
                #parse the sections in the segment
                for sec in cmd[2]:
                    sec2 = sec.__dict__["_objects_"]

                    #parse the flags of sections into human-readable text
                    # There is a type flag and one or more attribute flags in the 4-byte field
                    sec2["flags"] = self.parseSectionFlags(sec2["flags"])

                    #add the section to the list
                    sections.append(sec.__dict__["_objects_"])
            else:
                c["strings"] = cmd[2]
                if isinstance(c["strings"], str): #these strings are ASCII, and sometimes they don't play well with UTF-8
                    c["strings"] = c["strings"].decode('utf-8', 'ignore')

            results.append(c) #add the command to the list
            i += 1


        return (results, sections)

    def getMemProt(self, flags):
        #check to see if it has a single dict value
        if not data.VM_PROT.get(flags) is None:
            return data.VM_PROT.get(flags)
        else:
            f = '' #string to hold the flags
            for i in range(0, 31): #flags are each one bit, so check each bit in 4 bytes
                mask = 1 << i
                flag = flags & mask
                if flag in data.VM_PROT and flag != 0:
                    if f != '':
                        f += ", "
                    f += data.VM_PROT.get(flag)
            return f

    def parseSectionFlags(self, flags):
        f = '' #variable to store all the flags in

        #get the type - stored in the lowest byte
        type = data.SECTION_TYPES.get(flags & 0x000000ff)
        if not type is None:
            f += type

        #get the user-settable attributes - highest byte
        a1 = data.SECTION_ATTR.get(flags & 0xff000000)
        if not a1 is None:
            f += ", " + a1

        #get the system-settable attributes - middle two bytes
        a2 = data.SECTION_ATTR.get(flags & 0x00ffff00)
        if not a2 is None:
            f += ", " + a2

        return f


    def parseSymbolTable(self, sym_cmd, dyn_cmd, file_object, header):
        if dyn_cmd is None or sym_cmd is None:
            return
        try:
            offset = header.offset
            endian = header.endian
            # The symbol table is actually made up of several partitions. These partitions and their offsets
            # are listed in the LC_DYSYMTAB load command.
            symbols = []
            # the human-readable string of the symbol table are actually stored in the strings table, so get those
            #go to the beginning of the strings table, offset from the beginning of the Mach-O object
            file_object.seek(0)
            file_object.seek(sym_cmd.stroff+offset)
            #file_object.seek(sym_cmd.stroff, offset) #for some reason this throws an IOError
            strs = file_object.read(sym_cmd.strsize) #read in the entire string table
            #each string is null (00) terminated, so you can split on that
            # however the indexes to the string table are byte offsets, so this is not necessary really
            # strings = strs.split('\x00')

            # go to the beginning of the symbol table
            file_object.seek(0)
            file_object.seek(sym_cmd.symoff+offset)
            undef = [] #undefined external symbols
            defined = [] #defined external symbols
            #seek to the beginning index of the defined external symbols
            for i in xrange(dyn_cmd.iextdefsym):
                file_object.read(12)
                #if this is a 64-bit object file, there will be an extra 4 blank bytes
                if isinstance(header.header, mach_header_64):
                    file_object.read(4)

            #read the number of defined external symbols specified in LC_DYSYMTAB
            for i in xrange(dyn_cmd.nextdefsym):
                # get the index to the strings table - this is 4 bytes long
                t = file_object.read(4)
                # the endian of the Mach-O object is in the header
                index = struct.unpack(endian+'L', t)[0]
                #indirect.append(''.join('%02x' % ord(byte) for byte in t))
                file_object.read(8) #skip the rest of the symbol table entry - 8 bytes total
                #if this is a 64-bit object file, there will be an extra 4 blank bytes
                if isinstance(header.header, mach_header_64):
                    file_object.read(4)

                if index == 0: # a null string has an index of 0
                    defined.append('NULL')
                else: #get the human-readable string at the index
                    str = ''
                    b = strs[index]
                    i = 0
                    while (b != b'\x00'):
                        str = str + b
                        i += 1
                        b = strs[index+i]
                    defined.append(str)

            #read the number of undefined external symbols specified in LC_DYSYMTAB
            for i in xrange(dyn_cmd.nundefsym):
                # get the index to the strings table - this is 4 bytes long
                t = file_object.read(4)
                # the endian of the Mach-O object is in the header
                index = struct.unpack(endian+'L', t)[0]
                #indirect.append(''.join('%02x' % ord(byte) for byte in t))
                file_object.read(8) #skip the rest of the symbol table entry - 8 bytes total
                #if this is a 64-bit object file, there will be an extra 4 blank bytes
                if isinstance(header.header, mach_header_64):
                    file_object.read(4)

                if index == 0: # a null string has an index of 0
                    undef.append('NULL')
                else: #get the human-readable string at the index
                    str = ''
                    b = strs[index]
                    i = 0
                    while (b != b'\x00'):
                        str = str + b
                        i += 1
                        b = strs[index+i]
                    undef.append(str)
        except:
            defined = "Error: malformed symbol table"
            undef = []

        return (defined, undef)

    def getFlags(self, flags):
        f = '' #string to hold the flags
        for i in range(0, 31): #flags are each one bit, so check each bit in 4 bytes
            mask = 1 << i
            flag = flags & mask
            if flag in data.MACHO_FLAGS:
                if f != '':
                    f += ", "
                f += data.MACHO_FLAGS.get(flag)
        return f

    def parseFATHeader(self, f, pFile):
        results = {}
        #If this is a FAT file, it will have an extra header
        if not (pFile.fat is None):

            #insert the main FAT header fields
            results["Magic"] = pFile.fat.magic
            results["n_arch"] = pFile.fat.nfat_arch

            #seek past the first couple FAT header fields (2 fields, 4 bytes each)
            f.seek(8)
            #parse the sub-file object structures (fat_arch structures)
            archs = [fat_arch.from_fileobj(f) for i in range(pFile.fat.nfat_arch)]
            a_results = {}
            for a in archs:
                ar = {}
                #get human-readable names
                cpu_type = CPU_TYPE_NAMES.get(a.cputype, a.cputype)
                cpu_stype = self.getCPUSubtype(cpu_type, a.cpusubtype)

                ar["cpu_subtype"] = cpu_stype
                ar["offset"] = a.offset
                ar["size"] = a.size
                ar["alignment"] = a.align
                a_results[cpu_type] = ar

            results["archs"] = a_results

        return results

    '''Get the human-readable cpu subtype.
    This is a bit complicate because there seems to be no defined mapping for cpu_type to cpu_subtype, so I had to guess for some.
    ctype = human-readable cpu_type
    stype = cpu_subtype '''
    def getCPUSubtype(self, ctype, stype):
        if 'ARM' in ctype:
            return data.CPU_SUBTYPE_ARM.get(stype)
        elif 'HPPA' in ctype:
            return data.CPU_SUBTYPE_HPPA.get(stype)
        elif 'i860' in ctype:
            return data.CPU_SUBTYPE_I860.get(stype)
        elif 'i386' in ctype:
            return data.CPU_SUBTYPE_I386.get(stype)
        elif 'MC68' in ctype:
            return data.CPU_SUBTYPE_MC680x0.get(stype)
        elif 'MC88' in ctype:
            return data.CPU_SUBTYPE_MC88000.get(stype)
        elif 'MC98' in ctype:
            return data.CPU_SUBTYPE_MC98000.get(stype)
        elif 'MIPS' in ctype:
            return data.CPU_SUBTYPE_MIPS.get(stype)
        elif 'PowerPC' in ctype:
            return data.CPU_SUBTYPE_POWERPC.get(stype)
        elif 'SPARC' in ctype:
            return data.CPU_SUBTYPE_SPARC.get(stype)
        elif 'VAX' in ctype:
            return data.CPU_SUBTYPE_VAX.get(stype)
        elif 'x86_64' in ctype:
            return data.CPU_SUBTYPE_X86_64.get(stype)
        elif 'x86' in ctype:
            return data.CPU_SUBTYPE_X86.get(stype)
        elif 'high' in ctype:
            data.CPU_SUBTYPE_HIGH.get(stype)
        else:
            return data.CPU_SUBTYPE_ANY.get(stype)


class StaticMac(Processing):
    """
    The class that is actually called by Cuckoo when the processing modules are run.
    It collects the results from the MachO class, which does all the real work.
    """

    def run(self):
        """
        Run the analysis.
        @return: results dict.
        """
        #This is the name of the subcontainer Cuckoo will use for the returned data
        self.key = "static_macho"
        static_macho = {} #the dictionary to store the results in

        if self.task["category"] == "file": #If cuckoo analyzes a file, not a URL
            if HAVE_MACHO and HAVE_MAGIC: #if the proper libraries are installed
                if not (self.file_path is None): #if the file exists
                    kind = magic.from_file(self.file_path) #get the file type
                    #if it is Mach-O, parse it. Note FAT files are listed as Mach-O with multiple architectures
                    if not (kind is None) and ("Mach-O" in kind):
                        static_macho = MachO_Parse(self.file_path).parse()
                    elif not (kind is None) and ("Zip" in kind): #could be an app file
                        log.info(".zip file found, checking for executables inside")
                        static_macho = self.handleZip()
                    else:
                        log.info("File is not Mach-O or FAT file, quitting module")

        return static_macho

    """
    .app files contain Mach-O files, but they have to be submitted as zips
    This attempts to analyze the main executable if it is a .app file.
    """
    def handleZip(self):
        root = os.environ["TMPDIR"]
        static_macho = {} #the dictionary to store the results in

        with ZipFile(self.file_path, "r") as archive:
            zipinfos = archive.namelist()

            if not len(zipinfos): #this is an empty zip file
                return static_macho

            try:
                exec_file = ""
                for z in zipinfos:
                    if z.endswith(".app") or z.endswith(".app/"): #there is an app file
                        # extract the Info.plist
                        try:
                            plist_path = archive.open(z + "Contents/Info.plist")
                            plist = plistlib.readPlist(plist_path)
                            exec_file = plist["CFBundleExecutable"]
                        except KeyError:
                            log.info("Malformed .app file " + z + ", aborting static analysis")
                        break

                if exec_file == "":
                    return static_macho

                for z in zipinfos:
                    if os.path.basename(z) == exec_file:
                        #write out the executable file with only read permissions
                        outpath = os.path.join(root, os.path.basename(z))
                        out1 = open(outpath, "w+")
                        out1.close()
                        os.chmod(outpath, 0664)
                        #write the file out
                        out2 = open(outpath, "w+")
                        bytes = archive.read(z)
                        out2.write(bytes)
                        out2.close()
                        #parse the file
                        static_macho = MachO_Parse(outpath).parse()
                        #delete the file
                        os.remove(outpath)

            except BadZipfile:
                log.error("Unable to open zip file")
                return static_macho
            except RuntimeError:
                return static_macho

