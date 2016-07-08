"""
Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
this work by or on behalf of the U.S. Government. 
NOTICE:
For five (5) years from  the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, and perform publicly and display publicly, by or on behalf of the Government. There is provision for the possible extension of the term of this license. Subsequent to that period or any extension granted, the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, distribute copies to the public, perform publicly and display publicly, and to permit others to do so. The specific term of the license can be identified by inquiry made to Sandia Corporation or DOE.
NEITHER THE UNITED STATES GOVERNMENT, NOR THE UNITED STATES DEPARTMENT OF ENERGY, NOR SANDIA CORPORATION, NOR ANY OF THEIR EMPLOYEES, MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LEGAL RESPONSIBILITY FOR THE ACCURACY, COMPLETENESS, OR USEFULNESS OF ANY INFORMATION, APPARATUS, PRODUCT, OR PROCESS DISCLOSED, OR REPRESENTS THAT ITS USE WOULD NOT INFRINGE PRIVATELY OWNED RIGHTS.
Any licensee of this software has the obligation and responsibility to abide by the applicable export control laws, regulations, and general prohibitions relating to the export of technical data. Failure to obtain an export control license or other authority from the Government may result in criminal liability under U.S. laws.
"""

import random
import logging
import time
from threading import Thread
import Quartz.CoreGraphics as CG
from AppKit import *

from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

class Human(Auxiliary, Thread):
    """Human after all"""

    def __init__(self):
        Thread.__init__(self)
        self.do_run = True
         #get the size of the screen
        rect = NSScreen.mainScreen().frame()
        self.width = int(rect.size.width)
        self.height = int(rect.size.height)

    def stop(self):
        self.do_run = False

    def run(self):
        while self.do_run:
            self.move_mouse()
            self.click_mouse()
            #sleep for one second
            time.sleep(1)

    """
    Move the mouse to a random place on screen.
    This moves at computer-speed, so any malware checking for movement speed will be alerted.
    """
    def move_mouse(self):
        x = random.randint(0, self.width)
        y = random.randint(0, self.height)
        #create the event
        move = CG.CGEventCreateMouseEvent(None, CG.kCGEventMouseMoved, CG.CGPointMake(x, y), CG.kCGMouseButtonLeft)
        #send the event
        CG.CGEventPost(CG.kCGHIDEventTap, move)

    def click_mouse(self):
        point = CG.CGPointMake(self.width/2, 250)
        # Move mouse to top-middle position.
        move = CG.CGEventCreateMouseEvent(None, CG.kCGEventMouseMoved, point, CG.kCGMouseButtonLeft)
        # Mouse down.
        down = CG.CGEventCreateMouseEvent(NULL, CG.kCGEventLeftMouseDown, point, CG.kCGMouseButtonLeft)
        # Mouse up.
        up = CG.CGEventCreateMouseEvent(NULL, CG.kCGEventLeftMouseUp, point, CG.kCGMouseButtonLeft)

        #send the events
        CG.CGEventPost(CG.kCGHIDEventTap, move)
        CG.CGEventPost(CG.kCGHIDEventTap, down)
        time.sleep(0.05)
        CG.CGEventPost(CG.kCGHIDEventTap, up)
