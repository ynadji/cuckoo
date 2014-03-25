#!/usr/bin/env python

import sys
from scapy.all import *
from gzadns import DNSGZA
from gzatcp import TCPGZA
from optparse import OptionParser
from signal import SIGINT
import logging

log = logging.getLogger(__name__)

def projectpath(libdir, filedir=__file__):
    """Path's relative to location of the file. Makes it so your scripts don't
    break when run from directories other than the root."""
    import os.path as p
    return p.normpath(p.join(p.dirname(p.realpath(filedir)), libdir))

gameargs = {'dns1': ['--take-n', '1', 'dns'],
            'dnsw': ['--dropall', '--whitelist', 'dns'],
            'tcpw': ['--dropall', '--whitelist', 'tcp'],
            'tcp1': ['--take-n', '1', 'tcp'],
            'tcp2': ['--take-n', '2', 'tcp'],
            'tcp3': ['--take-n', '3', 'tcp']
            }

def startgame(game, ip, iptablespath):
    vmnum = ip.split('.')[2]
    if game == 'none':
        return
    args = gameargs[game] + [str(vmnum)]

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

    # "source" needs to be handled differently since the ! needs to be placed
    # before the argument (-s) in newer versions of iptables.
    os.system('%s -t %s -I %s -d %s %s -m %s -p %s -j NFQUEUE --queue-num %s'
            % (iptablespath, table, chain, ip, source, transport, transport, vmnum))
    main(arglist=args)

def stopgame(gamepid, game, ip, iptablespath):
    vmnum = ip.split('.')[2]
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

    os.kill(gamepid, SIGINT)
    os.system('%s -t %s -D %s -d %s %s -m %s -p %s -j NFQUEUE --queue-num %s'
            % (iptablespath, table, chain, ip, source, transport, transport, vmnum))

def main(arglist=None):
    """main function for standalone usage"""
    usage = "usage: %prog [options] dns|tcp vmnum"
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
    parser.add_option('-i', '--iptables-rule', dest='iptables',
            action='store_true',
            default=False, help='Print out sample iptables rule')

    if arglist is None:
        (options, args) = parser.parse_args()
    else:
        (options, args) = parser.parse_args(arglist)

    if len(args) != 2:
        parser.print_help()
        return 2
    if args[0] != 'dns' and args[0] != 'tcp':
        parser.print_help()
        return 2
    if options.iptables:
        if args[0] == 'dns':
            args[0] = 'udp'
        for action in ['-A', '-D']:
            log.info('iptables %s FORWARD -d 192.168.%s.0/24 -m %s -p %s -j NFQUEUE --queue-num %s',
                    action, args[1], args[0], args[0], args[1])
        sys.exit(0)
    if options.taken >= 0 and options.dropn >= 0:
        parser.error('--take-n and --drop-n are mutually exclusive. Only use one.')

    # do stuff
    log.debug('Running %s on tap%s with options: %s', args[0], args[1], options)
    if args[0] == 'dns':
        g = DNSGZA(int(args[1]), options)
    elif args[0] == 'tcp':
        g = TCPGZA(int(args[1]), options)
    else:
        return 0

    g.startgame()
    sys.exit(0)

if __name__ == '__main__':
    sys.exit(main())
