#!/usr/bin/env python

import sys
from optparse import OptionParser
import urllib2

dnsurls = [
    'http://nadji.us',
    'http://loki.nadji.us',
    'http://www.google.com',
    'http://www.cc.gatech.edu',
]

ipurls = [
    'http://66.172.10.185', # loki
    'http://143.215.130.112', # srg
    'http://2.112.182.51/',   # white
]

def main():
    """main function for standalone usage"""
    usage = "usage: %prog [options] dns|tcp"
    parser = OptionParser(usage=usage)

    (options, args) = parser.parse_args()

    if len(args) != 1 and args[0] in ["dns", "tcp"]:
        parser.print_help()
        return 2

    urls = dnsurls if args[0] == "dns" else ipurls

    # do stuff
    for url in urls:
        try:
            urllib2.urlopen(url)
            sys.exit(0)
        except urllib2.URLError:
            sys.stderr.write('failed to connect to %s, trying next\n' % url)

if __name__ == '__main__':
    sys.exit(main())
