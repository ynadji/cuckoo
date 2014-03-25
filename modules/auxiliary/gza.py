# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging

from lib.cuckoo.common.abstracts import Auxiliary
from modules.auxiliary.libgza import gza

log = logging.getLogger(__name__)

class GZA(Auxiliary):
    def start(self):
        self.game = self.task.options["custom"]
        self.iptables = self.options.get("iptables", "/sbin/iptables")

        if self.game in gza.gameargs:
            log.info("Playing game %s on IP %s", self.game, self.machine.ip)
            self.gamepid = os.fork()
            if self.gamepid == 0:
                gza.startgame(self.game, self.machine.ip, self.iptables)

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """
        if self.game in gza.gameargs:
            log.info("Stopping game %s on IP %s using PID %s", self.game, self.machine.ip, self.gamepid)
            gza.stopgame(self.gamepid, self.game, self.machine.ip, self.iptables)
