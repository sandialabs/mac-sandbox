"""
“Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
this work by or on behalf of the U.S. Government. 
NOTICE:
For five (5) years from  the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, and perform publicly and display publicly, by or on behalf of the Government. There is provision for the possible extension of the term of this license. Subsequent to that period or any extension granted, the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, distribute copies to the public, perform publicly and display publicly, and to permit others to do so. The specific term of the license can be identified by inquiry made to Sandia Corporation or DOE.
NEITHER THE UNITED STATES GOVERNMENT, NOR THE UNITED STATES DEPARTMENT OF ENERGY, NOR SANDIA CORPORATION, NOR ANY OF THEIR EMPLOYEES, MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LEGAL RESPONSIBILITY FOR THE ACCURACY, COMPLETENESS, OR USEFULNESS OF ANY INFORMATION, APPARATUS, PRODUCT, OR PROCESS DISCLOSED, OR REPRESENTS THAT ITS USE WOULD NOT INFRINGE PRIVATELY OWNED RIGHTS.
Any licensee of this software has the obligation and responsibility to abide by the applicable export control laws, regulations, and general prohibitions relating to the export of technical data. Failure to obtain an export control license or other authority from the Government may result in criminal liability under U.S. laws.
"""

import time
import logging
import StringIO
from threading import Thread
import Quartz.CoreGraphics as CG

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile
from lib.api.screenshot import Screenshot

log = logging.getLogger(__name__)
SHOT_DELAY = 1

class Screenshots(Auxiliary, Thread):
    """Take screenshots."""

    def __init__(self):
        Thread.__init__(self)
        self.do_run = True

    def stop(self):
        """Stop screenshotting."""
        self.do_run = False

    def run(self):
        """Run screenshotting.
        @return: operation status.
        """
        if not Screenshot().have_pil():
            log.warning("Python Image Library is not installed, "
                        "screenshots are disabled")
            return False

        img_counter = 0
        img_last = None

        while self.do_run:
            time.sleep(SHOT_DELAY)
            try:
                img_current = Screenshot().take()
            except IOError as e:
                log.error("Cannot take screenshot: %s", e)
                continue

            if img_last:
                if Screenshot().equal(img_last, img_current):
                    continue
            img_counter += 1

            #send a return keystroke for installers
            self.sendKey(0x24)

            try:
                # workaround as PIL can't write to the socket file object :(
                tmpio = StringIO.StringIO()
                img_current.save(tmpio, format="PNG")
                tmpio.seek(0)
            except:
                log.exception("Unable to write screenshot to disk.")

            # now upload to host from the StringIO
            nf = NetlogFile("shots/%s.png" % str(img_counter).rjust(4, "0"))

            for chunk in tmpio:
                nf.sock.sendall(chunk)

            nf.close()

            img_last = img_current

        return True

    """
    Send a keyboard event to the system at large using the Quartz Event Service
    https://developer.apple.com/library/mac/documentation/Carbon/Reference/QuartzEventServicesRef/Reference/reference.html
    0x24 is Return/Enter (more keys at http://webnnel.googlecode.com/svn/trunk/lib/Carbon.framework/Versions/A/Frameworks/HIToolbox.framework/Versions/A/Headers/Events.h)
    Modifiers: (defined in http://www.opensource.apple.com/source/IOHIDFamily/IOHIDFamily-308/IOHIDSystem/IOKit/hidsystem/IOLLEvent.h)
    NX_ALPHASHIFTMASK	0x00010000
    NX_SHIFTMASK		0x00020000
    NX_CONTROLMASK		0x00040000
    NX_ALTERNATEMASK	0x00080000
    NX_COMMANDMASK		0x00100000
    NX_NUMERICPADMASK	0x00200000
    NX_HELPMASK		    0x00400000
    NX_SECONDARYFNMASK	0x00800000
    """
    def sendKey(self, key, modifiers=0x0):

        source = CG.CGEventSourceCreate(CG.kCGEventSourceStateCombinedSessionState)

        keyDown = CG.CGEventCreateKeyboardEvent(source, key, True)
        CG.CGEventSetFlags(keyDown, modifiers)
        keyUp = CG.CGEventCreateKeyboardEvent(source, key, False)

        CG.CGEventPost(CG.kCGAnnotatedSessionEventTap, keyDown)
        CG.CGEventPost(CG.kCGAnnotatedSessionEventTap, keyUp)

        #Apparently these lines are not needed on newer versions of PyObjC and cause a segfault
        #CG.CFRelease(keyUp)
        #CG.CFRelease(keyDown)
        #CG.CFRelease(source)

