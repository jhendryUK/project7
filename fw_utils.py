#!/usr/bin/env python

import os
import sys
import yaml
import itertools
from collections import OrderedDict

class ErrorConfigFileDoesNotExist(Exception):
    pass

class ErrorHostHasNoZonesDefined(Exception):
    pass

class ErrorZoneNotDefined(Exception):
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

        type_map = {'address': 'AddressGroups',
                    'network': 'NetworkGroups',
                    'port': 'PortGroups'}
        mapped_group = type_map[self._group_type]
        self.groups = []
        
        for config in configs:
            try:
                for name, ips in config[mapped_group].iteritems():
                    self.groups.append(name)
                    setattr(self, name, ips)
        
            except KeyError:
                pass


    def config(self, group_name, brief=False):
        """Generate a full or brief configuration for a group"""

        type_map = {'address': 'address-group',
                    'network': 'network-group',
                    'port': 'port-group'}
        mapped_group = type_map[self._group_type]
        config = ''

        if brief:
            config += "{0} group: {1}\n".format(self._group_type, group_name)
            for ip in getattr(self, group_name):
                config += "    {0}\n".format(ip)

        else:
            config += "edit firewall group {0} {1}\n".format(mapped_group, group_name)
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


class RuleManagement(object):
    
    def __iter__(self):
        return iter(self.rules)


    def _generate_sub_config(self, option, value):
        
        config = ''
        if isinstance(value, list):
            for subvalue in value:
                config += "      set {0} {1}\n".format(option, subvalue)

        else:
            if option == 'description':
                value = "\"{0}\"".format(value)
            config += "      set {0} {1}\n".format(option, value)

        return config


class RuleTemplates(RuleManagement):

    def __init__(self, configs):
        """Load all rule templates"""

        super(RuleManagement, self).__init__()
        
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


    def config(self, zone, fw_rules, brief=False):
        """Generate rule config for a zone"""

        config = ''

        if brief:
            pass
        else:
            config = "edit firewall name {0}\n".format(zone)
            config += "    set default-action reject\n"
            config += "    set enable-default-log\n"

            for rule_name in fw_rules[zone]:
                rule = getattr(self, rule_name)
                config += "   edit rule {0}\n".format(rule['number'])

                for option, value in rule.iteritems():
                    if option != 'number':
                        config += self._generate_sub_config(option, value)

                config += "      up\n"

            config += "   top\n"

        return config
            

class NATRules(RuleManagement):
    """Stores all NAT rules to be created"""

    def __init__(self, all_configs):

        super(RuleManagement, self).__init__()        
        self.rules = { 'source': {}, 'destination': {} }

        for config in all_configs:
            for rule_type in self.rules:
                try:
                    for rule_number, rule_data in config['NATRules'][rule_type].iteritems():
                        self.rules[rule_type][rule_number] = rule_data
                        setattr(self, "{0}_{1}".format(rule_type, rule_number), rule_data)
                    
                except KeyError:
                    pass

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
                config += self._generate_sub_config(option, value)

            config += "    top\n"

        return config


class FirewallHost(object):

    def __init__(self, custom_config_file, generic_config_file='config/generic.yaml'):
        """"""

        self._zones = []
        self._address_groups = []
        self._network_groups = []
        self._port_groups = []
        self._rules = {}

        custom_config = self._load_config(custom_config_file)
        generic_config = self._load_config(generic_config_file)
        all_configs = [generic_config, custom_config]

        try:
            role_config = self._load_config(custom_config['role'])
            all_configs.insert(1, role_config)
        except KeyError:
            pass

        self._yaml_address_groups = AddressGroups(all_configs)
        self._yaml_network_groups = NetworkGroups(all_configs)
        self._yaml_port_groups = PortGroups(all_configs)
        self._yaml_rule_templates = RuleTemplates(all_configs)
        self._yaml_nat_rules = NATRules(all_configs)

        self._prepare_zones(all_configs)


    def __iter__(self):
        return iter(self._rules)


    def _load_config(self, config_file):
        if os.path.isfile(config_file):
            return yaml.safe_load(open(config_file))
        else:
            raise ErrorConfigFileDoesNotExist(config_file)

    
    def _prepare_zones(self, configs):
        """Define zones for this firewall"""

        for config in configs:
            try:
                for zone in config['Zones']:
                    self._zones.append(zone)
            
            except KeyError:
                pass

        if not self._zones:
            raise ErrorHostHasNoZonesDefined()

        for src, dst in itertools.permutations(self._zones, 2):
            if src != 'Self':
                zone = "{0}-To-{1}".format(src, dst)
                self._rules[zone] = []


    def _define_groups(self):
        """Dynamically define all required groups for this firewall"""

        for zone in self._rules:
            for rule_name in self._rules[zone]:
                rule = getattr(self._yaml_rule_templates, rule_name)
                for direction in ['source', 'destination']:

                    try:
                        option = rule[direction]
                        if isinstance(option, list):
                            for single in option:
                                self._find_group_in_rule(single)
                        else:
                            self._find_group_in_rule(option)
                    
                    except KeyError:
                        pass


    def _find_group_in_rule(self, option):
        """If our rule contains a group add it to the groups list"""

        try:
            option_tree, option_type, data = option.split(' ')

            if option_tree == 'group':
                group_actions = {   'address-group': self._address_groups,
                                    'network-group': self._network_groups,
                                    'port-group': self._port_groups}
                
                if not data in group_actions[option_type]:
                    group_actions[option_type].append(data)

        except ValueError:
            pass


    def add_rule(self, zone, rule):
        """Add a rule to this firewall"""
        try:
            if not rule in self._rules[zone]:
                self._rules[zone].append(rule)
        
        except KeyError:
            raise ErrorZoneNotDefined(zone)


    def config(self, brief=False):
        self._define_groups()
        print self._address_groups
        print self._network_groups
        print self._port_groups
        
        for i in self:
            print self._rules[i]

