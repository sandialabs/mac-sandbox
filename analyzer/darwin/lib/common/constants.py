

import os
from lib.common.rand import random_string


ROOT = os.path.join(os.getenv("HOME"), random_string(6, 10))

PATHS = {"root"   : ROOT,
         "logs"   : os.path.join(ROOT, "logs"),
         "files"  : os.path.join(ROOT, "files"),
         "shots"  : os.path.join(ROOT, "shots"),
         "memory" : os.path.join(ROOT, "memory"),
         "drop"   : os.path.join(ROOT, "drop")}

PIPE = os.path.join(os.getenv("TMPDIR"), random_string(6, 10))
SHUTDOWN_MUTEX = "Global/" + random_string(6, 10)
