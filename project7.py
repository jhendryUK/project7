#!/usr/bin/env python

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
                                    epilog="Example: {0} --config examples/simple_example.yaml".format(sys.argv[0]))
    parser.add_argument('-b', '--brief', dest='brief', action='store_true', default=False, help='Print a brief view of the firewall')
    parser.add_argument('-c', '--commit', dest='commit', action='store_true', default=False, help='Change the action of the .vbash script to commit')
    parser.add_argument('-g', '--generic', dest='generic', action='store', default='examples/simple_example.yaml', help='Path to the generic configuration file')
    parser.add_argument('-s', '--save', dest='save', action='store_true', default=False, help='Add a save option to the end of the .vbash script')
    parser.add_argument('--config', dest='config', default=False, help='Config to generate a firewall from')
    args = parser.parse_args()

    all_config_files = [args.generic]

    if args.config:
        fw_config_file = args.config
        all_config_files.append(fw_config_file)
    else:
        fw_config_file = args.generic
        
    firewall = fw_utils.FirewallHost(all_config_files)
    fw_config = firewall.config(args.brief)

    if args.brief:
        print fw_config
    else:
        SaveFirewallConfig(GenerateVBashConfig(fw_config, args), fw_config_file.replace('.yaml', '.vbash'))

if __name__ == '__main__':
    main()
