#!/usr/bin/env python
#
# DNS gameplay

from scapy.all import *
import sys,os,time
import nfqueue
import socket
from gzacommon import GZA

class DNSGZA(GZA):
    def __init__(self, vmnum, opts):
        super(DNSGZA, self).__init__(vmnum, opts)

        if self.game == 'dropn':
            self.log.error('--drop-n not implemented in %s, terminating',
                    self.__class__.__name__)
            sys.exit(2)
        elif self.game == 'taken':
            self.count = self.opts.taken

    def reset(self, signum, frame):
        if self.game == 'taken':
            self.log.error('Reset self.count in %s', self.__class__.__name__)
            self.count = self.opts.taken
        super(DNSGZA, self).reset(signum, frame)

    def remove_computed_fields(self, pkt):
        """Remove UDP computed fields"""
        del(pkt[IP].chksum)
        del(pkt[UDP].chksum)
        del(pkt[IP].len)
        del(pkt[UDP].len)

    def nxdomain(self, qpkt):
        """Modifies qpkt to return NXDomain"""
        qpkt[DNS].an = None
        qpkt[DNS].ns = None
        qpkt[DNS].ar = None
        qpkt[DNS].ancount = 0
        qpkt[DNS].nscount = 0
        qpkt[DNS].arcount = 0
        qpkt[DNS].rcode = "name-error"
        self.remove_computed_fields(qpkt)

    def forge(self, packet):
        self.log.debug('NXDomain for %s on %s', packet[DNSQR].qname, packet[IP].dst)
        self.nxdomain(packet)
        return True

    # spoof function
    def spoof(self, packet):
        """If we have a DNS response, change it to NXDomain."""
        dns = packet[DNS]
        dnsqr = packet[DNSQR]
        self.log.debug("Domain name: %s", dnsqr.qname)

        # We ALWAYS want to ignore this. Consider the game of accept the first
        # DNS request and spoof the rest. We are trying to attack malware
        # that's first DNS request is a rest of network connectivity.
        # It's unlikely to be the Windows NTP server.
        # Furthermore, if we disable the time lookup we could introduce addtnl
        # problems due to malware noticing a clock discrepancy. To be safe,
        # this should be a hardcoded case.
        if dnsqr.qname == 'time.windows.com.':
            return False

        if self.opts.whitelist and self.whitelisted(dnsqr.qname):
            self.log.debug('%s is whitelisted', dnsqr.qname)
            return False
        # Handle dropall game
        if self.game == 'dropall':
            return self.forge(packet)
        elif self.game == 'taken':
            if self.gamestate[dnsqr.qname] == 'whitelisted':
                self.log.debug("%s was a --take-n packet, accepting", dnsqr.qname)
                return False
            # Game over, reject all from now on
            elif self.count == 0:
                return self.forge(packet)
            else:
                self.count -= 1
                self.gamestate[dnsqr.qname] = 'whitelisted'
                self.log.debug('--take-n, let the packet through. %d more free packets left!',
                        self.count)
                return False

        self.log.debug('Fell through game ifelif chain, do not spoof')
        return False

    def playgame(self, payload):
        data = payload.get_data()
        packet = IP(data)
        if packet.haslayer(DNS) and self.spoof(packet):
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))
            return
        else:
            payload.set_verdict(nfqueue.NF_ACCEPT)
            return
