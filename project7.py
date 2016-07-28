#!/usr/bin/env python

import os
import sys
import argparse
import fw_utils

def GenerateVBashConfig(config):
    """Generate a .vbash script containing the zonepoicy"""

    config = """#!/bin/vbash
source /opt/vyatta/etc/functions/script-template
configure

{0}

# Replace compare with either commit or commit-confirm
compare

exit
""".format(config)
    
    return config


def SaveFirewallConfig(fw_config, fw_file):
    """Saves the firewall config ready to be commited"""

    with open(fw_file, 'w') as fh:
        fh.write(fw_config)
    
    os.chmod(fw_file, 0755)
    
    print "\nFirewall written to {0}\n".format(fw_file)


def main():

    parser = argparse.ArgumentParser(description='Generates a VyOS Zone Firewall',
                                    epilog="Example: {0} --host config/hosts/london/router1.yaml".format(sys.argv[0]))
    parser.add_argument('-b', '--brief', dest='brief', action='store_true', default=False, help='Print a the brief view of the firewall')
    parser.add_argument('--host', dest='host', required='true', help='Host to generate the firewall for')
    args = parser.parse_args()

    firewall = fw_utils.FirewallHost(args.host)
    fw_config = firewall.config(args.brief)

    if args.brief:
        print fw_config
    else:
        SaveFirewallConfig(GenerateVBashConfig(fw_config), args.host.replace('.yaml', '.vbash'))

if __name__ == '__main__':
    main()
