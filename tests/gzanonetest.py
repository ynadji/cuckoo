#!/usr/bin/env python

import sys
from optparse import OptionParser
import urllib2

dnsurl = 'http://loki.nadji.us'
ipurl  = 'http://66.172.10.185' # loki

def main():
    """main function for standalone usage"""
    usage = "usage: %prog [options] dns|tcp"
    parser = OptionParser(usage=usage)

    (options, args) = parser.parse_args()

    if len(args) != 1 and args[0] in ["dns", "tcp"]:
        parser.print_help()
        return 2

    url = dnsurl if args[0] == "dns" else ipurl

    # do stuff
    while True:
        try:
            urllib2.urlopen(url)
            return 0
        except urllib2.URLError:
            sys.stderr.write('failed to connect to %s, trying next\n' % url)

if __name__ == '__main__':
    sys.exit(main())
