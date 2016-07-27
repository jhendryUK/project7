#!/usr/bin/env python

import os
import sys
import yaml
from collections import OrderedDict

class ErrorConfigFileDoesNotExist(Exception):
    pass

class GroupManagement(object):
    
    def __iter__(self):
        return iter(self.groups)


    def __str__(self):
        
        config = ''
        for group in self:
            config += self.config(group, brief=True)

        return config


    def _load_groups(self, configs):

        self.groups = []
        type_map = {'address': 'AddressGroups',
                    'network': 'NetworkGroups',
                    'port': 'PortGroups'}
        
        for config in configs:
            try:
                for name, ips in config[type_map[self._group_type]].iteritems():
                    self.groups.append(name)
                    setattr(self, name, ips)
        
            except KeyError:
                pass


    def config(self, group_name, brief=False):
        """Generate a full or brief configuration for a group"""

        config = ''
        type_map = {'address': 'address-group',
                    'network': 'network-group',
                    'port': 'port-group'}

        if brief:
            config += "{0} group: {1}\n".format(self._group_type, group_name)
            for ip in getattr(self, group_name):
                config += "    {0}\n".format(ip)

        else:
            config += "edit firewall group {0} {1}\n".format(type_map[self._group_type], group_name)
            for value in getattr(self, group_name):
                config += "    set {0} {1}\n".format(self._group_type, value)
            config += '    top\n'
            
        return config


class AddressGroups(GroupManagement):
    
    def __init__(self, configs):
        """Load all AddressGroups from config files"""
        super(GroupManagement, self).__init__()
        self._group_type = 'address'
        self._load_groups(configs)


class NetworkGroups(GroupManagement):
    
    def __init__(self, configs):
        """Load all NetworkGroups from config file"""
        super(GroupManagement, self).__init__()
        self._group_type = 'network'
        self._load_groups(configs)


class PortGroups(GroupManagement):
    
    def __init__(self, configs):
        """Load all PortGroups from config file"""
        super(GroupManagement, self).__init__()
        self._group_type = 'port'
        self._load_groups(configs)


class RuleTemplates(object):

    def __init__(self, configs):
        """Load all rule templates"""
        
        self.rules = []
        for config in configs:
            try:
                for name, options in config['RuleTemplates'].iteritems():
                    self.rules.append(name)
                    setattr(self, name, options)

            except KeyError:
                pass


    def __str__(self):
        return "\n".join(self.rules)


    def __iter__(self):
        return iter(self.rules)


    def config(self, zone, fw_rules, brief=False):
        """Generate rule config for a zone"""

        config = ''

        if brief:
            pass
        else:
            config = "edit firewall name {0}\n".format(zone)
            config += "    set default-action reject\n"
            config += "    set enable-default-log\n"
            

class NATRules(object):
    """Stores all NAT rules to be created"""

    def __init__(self, all_configs):
        
        self.rules = { 'source': {}, 'destination': {} }

        for config in all_configs:
            for rule_type in self.rules:
                try:
                    for rule_number, rule_data in config['NATRules'][rule_type].iteritems():
                        self.rules[rule_type][rule_number] = rule_data
                        setattr(self, "{0}_{1}".format(rule_type, rule_number), rule_data)
                    
                except KeyError:
                    pass

    def __iter__(self):
        return iter(self.rules)


    def __str__(self):
        
        config = ''
        for nat_type in self.rules:
            config += "{0} nat's:\n".format(nat_type)
            for nat_number in self.rules[nat_type]:
                desc = self.rules[nat_type][nat_number].get('description', 'No Description Available')
                config += "    {0}: {1}\n".format(nat_number, desc)
            config += '\n'

        return config


    def config(self, rule_type, rule_number, brief=False):
        """Generate configuration for all NAT rules"""

        config = ''
        if brief:
            description = self.rules[rule_type][rule_number]['description']
            config += "   {0}: {1}\n".format(rule_number, description)
        
        else:
            config += "edit nat {0} rule {1}\n".format(rule_type, rule_number)
            for option, value in self.rules[rule_type][rule_number].iteritems():
                if isinstance(value, list):
                    for subvalue in value:
                        config += "   set {0} {1}\n".format(option, subvalue)
                else:
                    if option == 'description':
                        value = "\"{0}\"".format(value)
                    config += "   set {0} {1}\n".format(option, value)

            config += "   top\n"

        return config


class FirewallHost(object):

    def __init__(self, custom_config_file):
        """"""

        custom_config = self._load_yaml_config(custom_config_file)
        generic_config = self._load_yaml_config('examples/generic.yaml')
        all_configs = [generic_config, custom_config]

        try:
            role_config = self._load_yaml_config(custom_config['role'])
            all_configs.insert(1, role_config)
        except KeyError:
            pass

        self.yaml_address_groups = AddressGroups(all_configs)
        self.yaml_network_groups = NetworkGroups(all_configs)
        self.yaml_port_groups = PortGroups(all_configs)
        self.yaml_rule_templates = RuleTemplates(all_configs)
        self.yaml_nat_rules = NATRules(all_configs)

    def _load_yaml_config(self, config_file):
        if os.path.isfile(config_file):
            return yaml.safe_load(open(config_file))
        else:
            raise ErrorConfigFileDoesNotExist(config_file)


