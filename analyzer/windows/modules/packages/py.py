# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Py(Package):
    """Python analysis package."""

    def start(self, path):
        free = self.options.get("free", False)
        args = self.options.get("arguments", None)
        suspended = True
        if free:
            suspended = False

        # prepend .py path to args
        if args:
            args = "%s %s" % (path, args)
        else:
            args = path

        p = Process()
        # sys.executable is the path to the current running python executable
        if not p.execute(path=sys.executable, args=args, suspended=suspended):
            raise CuckooPackageError("Unable to execute Python.exe, analysis aborted")

        if not free and suspended:
            p.inject()
            p.resume()
            return p.pid
        else:
            return None

    def check(self):
        return True

    def finish(self):
        return True
