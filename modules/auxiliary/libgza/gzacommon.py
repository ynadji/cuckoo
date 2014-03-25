import os
import sys
import nfqueue
import socket
import signal
import time
import whitelist
from collections import defaultdict
import logging

class GZA(object):
    def __init__(self, vmnum, opts):
        self.gamestate = defaultdict(int)
        self.vmnum = vmnum
        #self.iface = 'tap%d' % vmnum
        self.iface = 'virbr1'
        self.opts = opts
        self.mac = '52:54:00:1D:3A:4F'
        self.log = logging.getLogger(__name__)

        if self.opts.whitelist:
            whitelist.makewhitelist(self.opts.whitelistpath)
            self.whitelisted = whitelist.whitelisted
            whitelist.makeipwhitelist(self.opts.ipwhitelistpath)
            self.whitelistedip = whitelist.whitelistedip

        # Set the game (only used in subclass games)
        if self.opts.taken > 0:
            self.game = 'taken'
        elif self.opts.dropn > 0:
            self.game = 'dropn'
        elif self.opts.dropall:
            self.game = 'dropall'

    def reset(self, signum, frame):
        self.log.debug('Cleared game state!')
        self.gamestate.clear()
        try:
            self.q.try_run()
        except KeyboardInterrupt:
            self.log.debug('Clean shutdown')
            self.q.unbind(socket.AF_INET)
            sys.exit(0)

    def playgame(self, payload):
        payload.set_verdict(nfqueue.NF_ACCEPT)

    def startgame(self):
        good = False
        while not good:
            try:
                self.q = nfqueue.queue()
                self.q.open()
                self.q.set_callback(self.playgame)
                self.q.fast_open(self.vmnum, socket.AF_INET)
                good = True
            except RuntimeError as e:
                self.log.error(str(e))
                self.log.error('Retrying to connect to nfqueue #%d...', self.vmnum)
                time.sleep(3)
        try:
            self.log.debug('Successfully bound to nfqueue #%d', self.vmnum)
            self.q.try_run()
        except KeyboardInterrupt:
            self.log.debug('Clean shutdown')
            self.q.unbind(socket.AF_INET)
            os._exit(0)

