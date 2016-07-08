"""
Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
this work by or on behalf of the U.S. Government. 
NOTICE:
For five (5) years from  the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, and perform publicly and display publicly, by or on behalf of the Government. There is provision for the possible extension of the term of this license. Subsequent to that period or any extension granted, the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, distribute copies to the public, perform publicly and display publicly, and to permit others to do so. The specific term of the license can be identified by inquiry made to Sandia Corporation or DOE.
NEITHER THE UNITED STATES GOVERNMENT, NOR THE UNITED STATES DEPARTMENT OF ENERGY, NOR SANDIA CORPORATION, NOR ANY OF THEIR EMPLOYEES, MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LEGAL RESPONSIBILITY FOR THE ACCURACY, COMPLETENESS, OR USEFULNESS OF ANY INFORMATION, APPARATUS, PRODUCT, OR PROCESS DISCLOSED, OR REPRESENTS THAT ITS USE WOULD NOT INFRINGE PRIVATELY OWNED RIGHTS.
Any licensee of this software has the obligation and responsibility to abide by the applicable export control laws, regulations, and general prohibitions relating to the export of technical data. Failure to obtain an export control license or other authority from the Government may result in criminal liability under U.S. laws.
"""

def choose_package(file_type, file_name):
    """Choose analysis package due to file type and file extension.
    @param file_type: file type.
    @return: package or None.
    """
    if not file_type:
        return None

    file_name = file_name.lower()

    if "Mach-O" in file_type:
        return "macho"
    elif "PDF" in file_type or file_name.endswith(".pdf"):
        return "pdf"
    elif "Microsoft Word" in file_type or \
         "Microsoft Office Word" in file_type or \
         file_name.endswith(".docx") or \
         file_name.endswith(".doc"):
        return "doc"
    elif "Rich Text Format" in file_type or file_name.endswith(".rtf") \
            or "property list" in file_type or file_name.endswith(".plist"):
        return "rtf"
    elif "HTML" in file_type or file_name.endswith(".htm") or file_name.endswith(".html"):
        return "html"
    elif file_name.endswith(".jar"):
        return "jar"
    elif "Zip" in file_type or file_name.endswith(".zip"):
        return "zip"
    elif file_name.endswith(".py") or "Python script" in file_type:
        return "python"
    else:
        return "generic"
