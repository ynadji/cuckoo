#!/usr/bin/env python
#
# pool of nfqueues
#

import sys
import os
from optparse import OptionParser
import asyncore
from socket import AF_INET, AF_INET6, inet_ntoa
import logging

import nfqueue
from scapy.all import *

from gzadns import DNSGZA
from gzatcp import TCPGZA

log = logging.getLogger(__name__)

TCPW_OFFSET = 16

dnswgza = None
tcpwgza = None

gameargs = {'dns1': ['--take-n', '1', 'dns'],
            'dnsw': ['--dropall', '--whitelist', 'dns'],
            'tcpw': ['--dropall', '--whitelist', 'tcp'],
            'tcp1': ['--take-n', '1', 'tcp'],
            'tcp2': ['--take-n', '2', 'tcp'],
            'tcp3': ['--take-n', '3', 'tcp']
            }

def projectpath(libdir, filedir=__file__):
    """Path's relative to location of the file. Makes it so your scripts don't
    break when run from directories other than the root."""
    import os.path as p
    return p.normpath(p.join(p.dirname(p.realpath(filedir)), libdir))

class AsyncNfQueue(asyncore.file_dispatcher):
  """An asyncore dispatcher of nfqueue events.

  """

  def __init__(self, cb, nqueue=0, family=AF_INET, maxlen=5000, map=None):
    self._q = nfqueue.queue()
    self._q.set_callback(cb)
    self._q.fast_open(nqueue, family)
    self._q.set_queue_maxlen(maxlen)
    self.fd = self._q.get_fd()
    asyncore.file_dispatcher.__init__(self, self.fd, map)
    self._q.set_mode(nfqueue.NFQNL_COPY_PACKET)

  def handle_read(self):
    self._q.process_pending()

  # We don't need to check for the socket to be ready for writing
  def writable(self):
    return False

def exitqueues(signum, frame):
    log.debug('exiting nfqueue loop')
    sys.exit(0)

def makeoptions(game):
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option('-d', '--drop-n', dest='dropn', default=-1, action='store',
            type='int',
            help='"Block" first n packets and accept rest (-1 for ignore this rule) based on game type [default: %default]')
    parser.add_option('-t', '--take-n', dest='taken', default=-1, action='store',
            type='int',
            help='"Accept" first n packets and drop rest (-1 for ignore this rule) based on game type [default: %default]')
    parser.add_option('-a', '--dropall', dest='dropall', default=False,
            action='store_true', help='Drop all packets')
    parser.add_option('-w', '--whitelist', dest='whitelist', default=False,
            action='store_true', help='Use whitelist')
    parser.add_option('--whitelist-path', dest='whitelistpath',
            default=projectpath('./top1000.csv'), help='Whitelist to use [default: %default]')
    parser.add_option('--ip-whitelist-path', dest='ipwhitelistpath',
            default=projectpath('./generic-dnswl'), help='Whitelist to use [default: %default]')

    (options, args) = parser.parse_args(gameargs[game])
    return options

def startqueues(numqs=16):
    global TCPW_OFFSET
    global dnswgza
    global tcpwgza

    # vmnum doesn't matter anymore. all this shit needs a crazy refactor...
    dnswgza = DNSGZA(-1, makeoptions('dnsw'))
    tcpwgza = TCPGZA(-1, makeoptions('tcpw'))

    TCPW_OFFSET = numqs

    nfqueues = []
    for nqueue in range(1, numqs + 1):
        nfqueues.append(AsyncNfQueue(dnswgza.playgame, nqueue=nqueue))
    # tcpw nfqueues
    for nqueue in range(numqs + 1, numqs * 2 + 1):
        nfqueues.append(AsyncNfQueue(tcpwgza.playgame, nqueue=nqueue))

    log.info('Starting %d nfqueues', numqs * 2)
    asyncore.loop()

def addiptablesrule(game, ip):
    vmnum = int(ip.split('.')[2])
    if game == 'none':
        return

    if game.startswith('dns'):
        transport = 'udp'
        table = 'filter'
        chain = 'OUTPUT'
        source = ''
    else:
        transport = 'tcp'
        table = 'mangle'
        chain = 'POSTROUTING'
        source = '! -s 192.168.0.0/16'
        vmnum += TCPW_OFFSET

    # "source" needs to be handled differently since the ! needs to be placed
    # before the argument (-s) in newer versions of iptables.
    os.system('iptables -t %s -I %s -d %s %s -m %s -p %s -j NFQUEUE --queue-num %d'
            % (table, chain, ip, source, transport, transport, vmnum))

def removeiptablesrule(game, ip):
    vmnum = int(ip.split('.')[2])
    if game.startswith('dns'):
        transport = 'udp'
        table = 'filter'
        chain = 'OUTPUT'
        source = ''
    else:
        transport = 'tcp'
        table = 'mangle'
        chain = 'POSTROUTING'
        source = '! -s 192.168.0.0/16'
        vmnum += TCPW_OFFSET

    os.system('iptables -t %s -D %s -d %s %s -m %s -p %s -j NFQUEUE --queue-num %d'
            % (table, chain, ip, source, transport, transport, vmnum))

def main():
    """main function for standalone usage"""
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option('-d', '--drop-n', dest='dropn', default=-1, action='store',
            type='int',
            help='"Block" first n packets and accept rest (-1 for ignore this rule) based on game type [default: %default]')
    parser.add_option('-t', '--take-n', dest='taken', default=-1, action='store',
            type='int',
            help='"Accept" first n packets and drop rest (-1 for ignore this rule) based on game type [default: %default]')
    parser.add_option('-a', '--dropall', dest='dropall', default=False,
            action='store_true', help='Drop all packets')
    parser.add_option('-w', '--whitelist', dest='whitelist', default=False,
            action='store_true', help='Use whitelist')
    parser.add_option('--whitelist-path', dest='whitelistpath',
            default=projectpath('./top1000.csv'), help='Whitelist to use [default: %default]')
    parser.add_option('--ip-whitelist-path', dest='ipwhitelistpath',
            default=projectpath('./generic-dnswl'), help='Whitelist to use [default: %default]')

    (options, args) = parser.parse_args()

    if len(args) != 0:
        parser.print_help()
        return 2

    # do stuff
    startqueues()

if __name__ == '__main__':
    sys.exit(main())
