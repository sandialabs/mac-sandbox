"""
Copyright (2014) Sandia Corporation. Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive license for use of 
this work by or on behalf of the U.S. Government. 
NOTICE:
For five (5) years from  the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, and perform publicly and display publicly, by or on behalf of the Government. There is provision for the possible extension of the term of this license. Subsequent to that period or any extension granted, the United States Government is granted for itself and others acting on its behalf a paid-up, nonexclusive, irrevocable worldwide license in this data to reproduce, prepare derivative works, distribute copies to the public, perform publicly and display publicly, and to permit others to do so. The specific term of the license can be identified by inquiry made to Sandia Corporation or DOE.
NEITHER THE UNITED STATES GOVERNMENT, NOR THE UNITED STATES DEPARTMENT OF ENERGY, NOR SANDIA CORPORATION, NOR ANY OF THEIR EMPLOYEES, MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LEGAL RESPONSIBILITY FOR THE ACCURACY, COMPLETENESS, OR USEFULNESS OF ANY INFORMATION, APPARATUS, PRODUCT, OR PROCESS DISCLOSED, OR REPRESENTS THAT ITS USE WOULD NOT INFRINGE PRIVATELY OWNED RIGHTS.
Any licensee of this software has the obligation and responsibility to abide by the applicable export control laws, regulations, and general prohibitions relating to the export of technical data. Failure to obtain an export control license or other authority from the Government may result in criminal liability under U.S. laws.
"""

import math
import sys
import logging
import Quartz.CoreGraphics as CG
from AppKit import *
from Quartz import NSURL, CGImageDestinationCreateWithURL, CGImageDestinationAddImage, CGImageDestinationFinalize
from LaunchServices import kUTTypePNG
import os
import tempfile

sys.path.append('../common')

try:
    import ImageChops
    import Image
    import ImageOps
    HAVE_PIL = True
except:
    HAVE_PIL = False

log = logging.getLogger(__name__)

class Screenshot:
    """Get screenshots."""

    def have_pil(self):
        """Is Python Image Library installed?
        @return: installed status.
        """
        return HAVE_PIL

    def equal(self, img1, img2):
        """Compares two screenshots using Root-Mean-Square Difference (RMS).
        @param img1: screenshot to compare.
        @param img2: screenshot to compare.
        @return: equal status.
        """
        if not HAVE_PIL:
            return None

        # To get a measure of how similar two images are, we use
        # root-mean-square (RMS). If the images are exactly identical,
        # this value is zero.
        diff = ImageChops.difference(img1, img2)
        h = diff.histogram()
        sq = (value * ((idx % 256)**2) for idx, value in enumerate(h))
        sum_of_squares = sum(sq)
        rms = math.sqrt(sum_of_squares/float(img1.size[0] * img1.size[1]))

        # Might need to tweak the threshold. I have set it sensitive enough so that it should
        # detect installer changes but not so sensitive that it triggers every second with Activity Monitor open
        return rms < 50

    def take(self):
        """Take a screenshot.
        Unfortunately, PIL's screenshot functions are Windows-only.
        Most OS X solutions in Python involve loading an entire GUI library, like gtk or wxPython,
        or using the built-in screencapture program and then reading the screenshot from disk.
        In the interest of speed, I have tried to avoid those things by using PyObjC.
        @return: screenshot or None.
        """

        #get the size of the screen
        rect = NSScreen.mainScreen().frame()
        size = (int(rect.size.width), int(rect.size.height))

        try:
            image = CG.CGWindowListCreateImage(rect, CG.kCGWindowListOptionOnScreenOnly, CG.kCGNullWindowID, CG.kCGWindowImageDefault)
        except:
            log.exception("Unable to take screenshot.")

        # write the image to a temporary file in memory to save I/O performance
        f = tempfile.NamedTemporaryFile(mode='rwb+', delete=False)
        url = NSURL.fileURLWithPath_(f.name)
        destination = CGImageDestinationCreateWithURL(url, kUTTypePNG, 1, None)
        CGImageDestinationAddImage(destination, image, None)
        CGImageDestinationFinalize(destination)
        f.flush()
        f.seek(0)
        f.close()

        # Convert CGImage to PIL image for comparisons
        pil_image = Image.open(f.name)

        os.unlink(f.name)

        return pil_image

    def image_fix(self, image):
        #invert the color
        inverted_image = image
        """
        if image.mode == 'RGBA':
            r, g, b, a = image.split()
            rgb_image = Image.merge('RGB', (r,g,b))
            inverted_image = ImageOps.invert(rgb_image)
            r2, g2, b2 = inverted_image.split()
            inverted_image = Image.merge('RGBA', (r2,g2,b2,a))

        else: #this nice simple method only works with RGB
            inverted_image = ImageOps.invert(image)
        """

        # Rotate and flip horizontally to the correct orientation
        return inverted_image.rotate(180).transpose(Image.FLIP_LEFT_RIGHT)