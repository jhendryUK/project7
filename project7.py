#!/usr/bin/env python

"""
Project 7
VyOS Firewall/NAT/ZonePolicy config generator

Author: https://github.com/jhendryUK
"""

import os
import sys
import argparse
import fw_utils

def GenerateVBashConfig(config, args):
    """Generate a .vbash script containing the firewall config"""

    commit_action = 'commit\n' if args.commit else 'compare\n'
    commit_action += 'save\n' if args.save else ''

    config = """#!/bin/vbash
source /opt/vyatta/etc/functions/script-template
configure

{0}

# Action to take
{1}

exit
""".format(config, commit_action)
    
    return config


def SaveFirewallConfig(fw_config, fw_file):
    """Saves the firewall config ready to be commited"""

    with open(fw_file, 'w') as fh:
        fh.write(fw_config)
    
    os.chmod(fw_file, 0755)
    
    print "\nFirewall written to {0}\n".format(fw_file)


def main():

    parser = argparse.ArgumentParser(description='Generates a VyOS Zone Firewall',
                                    epilog="Example: {0} --config examples/simple_firewall.yaml".format(sys.argv[0]))
    parser.add_argument('-b', '--brief', dest='brief', action='store_true', default=False, help='Print a brief view of the firewall')
    parser.add_argument('-c', '--commit', dest='commit', action='store_true', default=False, help='Change the action of the .vbash script to commit')
    parser.add_argument('-s', '--save', dest='save', action='store_true', default=False, help='Add a save option to the end of the .vbash script')
    parser.add_argument('--config', dest='config', required=True, help='Config to generate a firewall from')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    firewall = fw_utils.FirewallHost(args.config)
    fw_config = firewall.config(args.brief)

    if args.brief:
        print fw_config
    else:
        SaveFirewallConfig(GenerateVBashConfig(fw_config, args), args.config.replace('.yaml', '.vbash'))

if __name__ == '__main__':
    known_exceptions = (fw_utils.ErrorConfigFileDoesNotExist,
                        fw_utils.ErrorNoZonesDefined,
                        fw_utils.ErrorZoneNotDefined,
                        fw_utils.ErrorUnknownGroupType,
                        fw_utils.ErrorGroupNotDefined,
                        fw_utils.ErrorRedefiningRuleTemplate,
                        fw_utils.ErrorRedefiningRuleTemplateNumber,
                        fw_utils.ErrorNotDefinedSelfOutboundPolicy,
                        fw_utils.ErrorZoneHasNoInterfaces,
                        fw_utils.ErrorRuleNotDefined)
    try:
        main()
    except known_exceptions, e:
        print "Error: {0}".format(e.message())
        
