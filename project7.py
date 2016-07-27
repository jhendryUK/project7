#!/usr/bin/env python

import fw_utils

if __name__ == '__main__':
    firewall = fw_utils.FirewallHost('examples/hosts/london/router1.yaml')

    print firewall.yaml_address_groups
    print firewall.yaml_network_groups
    print firewall.yaml_port_groups
    print firewall.yaml_rule_templates
    print firewall.yaml_rule_templates.ALLOW_TRUSTED_TRAFFIC
    print firewall.yaml_nat_rules
