#!/usr/bin/env python
#
# Test for DGA behavior. Argument domain (foo.com) should have a wildcard
# subdomain (*.foo.com) that is NOT on the whitelist. Terminates when a
# resolution is successful.

import sys
from optparse import OptionParser
import urllib2

def main():
    """main function for standalone usage"""
    usage = "usage: %prog [options] wildcardsubs"
    parser = OptionParser(usage=usage)

    (options, args) = parser.parse_args()

    if len(args) != 1:
        parser.print_help()
        return 2

    num = 0

    # do stuff
    while True:
        url = 'http://%d.%s' % (num, args[0])
        try:
            urllib2.urlopen(url)
            return 0
        except urllib2.URLError:
            sys.stderr.write('failed to connect to %s, trying next\n' % url)
            num += 1

if __name__ == '__main__':
    sys.exit(main())
