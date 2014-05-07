#!/usr/bin/env python
#
# Make gza-network.xml
#
# TODO: think of a better network organization so you can have more VMs
#

import sys
from optparse import OptionParser

def main():
    """main function for standalone usage"""
    usage = "usage: %prog [options] > gza-network.xml; sudo virsh net-define gza-network.xml"
    parser = OptionParser(usage=usage)
    parser.add_option('-n', '--numvms', default=255, type='int',
            help='Number of VMs to handle in the network configuration')

    (options, args) = parser.parse_args()

    if len(args) != 0:
        parser.print_help()
        return 2

    header = """<network>
  <name>gza</name>
  <uuid>5e82fe38-1ad3-2892-2bec-373ca31b1d3a</uuid>
  <forward mode='route'/>
  <bridge name='virbr1' stp='on' delay='0' />
  <mac address='52:54:00:6D:E6:8D'/>
  <dns>
    <host ip='8.8.8.8'>
    </host>
  </dns>
  <ip address='192.168.0.1' netmask='255.255.0.0'>
    <dhcp>
      <range start='192.168.0.2' end='192.168.255.254' />"""
    footer = """    </dhcp>
  </ip>
</network>"""

    entry = "      <host mac='aa:bb:cc:dd:ee:%s' name='gza%d' ip='192.168.%d.1' />"

    # do stuff
    print(header)
    for i in range(options.numvms):
        print(entry % (hex(i).split('x')[1], i, i + 1))
    print(footer)

if __name__ == '__main__':
    sys.exit(main())
