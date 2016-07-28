#!/usr/bin/env python

import argparse
import fw_utils

def BaseRuleSet(fw):
    
    for zone in fw:
        print zone
        fw.add_rule(zone, 'ALLOW_ESTABLISHED')
        fw.add_rule(zone, 'ALLOW_RELATED')
        fw.add_rule(zone, 'DROP_INVALID_STATE')

        fw.add_rule(zone, 'ALLOW_ICMP_ECHO_REPLY')
        fw.add_rule(zone, 'ALLOW_ICMP_DEST_UNRECH')
        fw.add_rule(zone, 'ALLOW_ICMP_QUENCH')
        fw.add_rule(zone, 'ALLOW_ICMP_ECHO_REQUEST')
        fw.add_rule(zone, 'ALLOW_ICMP_TIME_EXCEEDED')
        fw.add_rule(zone, 'DROP_ICMP')

    return fw

if __name__ == '__main__':
    firewall = fw_utils.FirewallHost('config/hosts/london/router1.yaml')

#    firewall = BaseRuleSet(firewall)
#    firewall.add_rule('Servers-To-External', 'ALLOW_RFC1918_SSH')
#    firewall.add_rule('Servers-To-External', 'ALLOW_CONNTRACK_SYNC_UNICAST')
    print firewall.config()
