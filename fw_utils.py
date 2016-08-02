#!/usr/bin/env python

"""
Exposes classes used to generate a VyOS Zone Firewall and NAT rules
"""

import yaml
import itertools
from collections import OrderedDict

class ErrorConfigFileDoesNotExist(Exception):
    pass

class ErrorHostHasNoZonesDefined(Exception):
    pass

class ErrorZoneNotDefined(Exception):
    pass

class ErrorUnknownGroupType(Exception):
    pass

class ErrorGroupNotDefined(Exception):
    pass

class ErrorRedefiningRuleTemplate(Exception):
    pass

class ErrorRedefiningRuleTemplateNumber(Exception):
    pass

class ErrorNotDefinedSelfOutboundPolicy(Exception):
    pass

class ErrorZoneHasNoInterfaces(Exception):
    pass

class GroupManager(object):
    """
    Holds the groups for a group type and can print the brief view or full config
    
    Valid group types are:
        address
        network
        port
    """

    def __init__(self, group_type, configs):
        """Validate group type and load all groups from it"""
        
        if not group_type in ['address', 'network', 'port']:
            raise ErrorUnknownGroupType(group_type)

        self.groups = []
        self._group_type = group_type
        self._load_groups(configs)
    

    def __iter__(self):
        """Return an iter() of all group names"""
        return iter(self.groups)


    def __str__(self):
        """Return a str() of the brief view of all groups"""
        
        config = ''
        for group in self:
            config += self.config(group, brief=True)

        return config


    def _load_groups(self, configs):
        """Load all groups for a group type"""

        type_map = {'address': 'AddressGroups',
                    'network': 'NetworkGroups',
                    'port': 'PortGroups'}
        mapped_group = type_map[self._group_type]
        
        for config in configs:
            try:
                for name, ips in config[mapped_group].iteritems():
                    self.groups.append(name)
                    setattr(self, name, ips)
        
            except (AttributeError, KeyError, TypeError):
                pass


    def config(self, group_name, brief=False):
        """Return a str() with either a brief view or full config for a group"""

        type_map = {'address': 'address-group',
                    'network': 'network-group',
                    'port': 'port-group'}
        mapped_group = type_map[self._group_type]
        config = ''

        if brief:
            config += "{0} group: {1}\n".format(self._group_type, group_name)
            try:
                for ip in getattr(self, group_name):
                    config += "    {0}\n".format(ip)
            except AttributeError:
                raise ErrorGroupNotDefined("{0} group not defined: {1}".format(self._group_type, group_name))

        else:
            config += "edit firewall group {0} {1}\n".format(mapped_group, group_name)
            try:
                for value in getattr(self, group_name):
                    config += "    set {0} {1}\n".format(self._group_type, value)
                config += '    top\n'
            except AttributeError:
                raise ErrorGroupNotDefined("{0} group not defined: {1}".format(self._group_type, group_name))
            
        return config


class RuleManager(object):
    """Shared functions for managing Firewall and NAT rules"""
    
    def __iter__(self):
        """Return an iter() of all rule names"""
        return iter(self.rules)


    def _generate_sub_config(self, option, value):
        
        config = ''
        if isinstance(value, list):
            for subvalue in value:
                config += "        set {0} {1}\n".format(option, subvalue)

        else:
            if option == 'description':
                value = "\"{0}\"".format(value)
            config += "        set {0} {1}\n".format(option, value)

        return config


class RuleTemplates(RuleManager):
    """Holds all rule templates and can print a breif view or full config"""

    def __init__(self, configs):
        """Load all rule templates"""

        super(RuleManager, self).__init__()
        
        self.rules = []
        for config in configs:
            try:
                for name, options in config['RuleTemplates'].iteritems():
                    self._look_for_redefined_rules(name, options)
                    self.rules.append(name)
                    setattr(self, name, options)

            except (AttributeError, KeyError, TypeError):
                pass


    def __str__(self):
        """Return a str() of all rule template names"""
        return "\n".join(self.rules)

    
    def _look_for_redefined_rules(self, name, options):
        """Raises an exception if a rule template name or rule number is being redefined"""

        if name in self.rules:
            raise ErrorRedefiningRuleTemplate("You have redefined rule {0}. This is dangerous and not allowed".format(name))

        new_number = options['number']
        for rule in self.rules:
            if new_number == getattr(self, rule)['number']:
               raise ErrorRedefiningRuleTemplateNumber("You are reusing rule number {0} in rule {1}. This is dangerous and not allowed".format(new_number, name))

    

    def config(self, zone, fw_rules, brief=False):
        """Returns a str() of either a brief view or full config for a rule template in a zone-pair"""

        config = ''

        if brief:
            for rule_name in fw_rules[zone]:
                config += "   {0}\n".format(rule_name)
        else:
            config = "edit firewall name {0}\n".format(zone)
            config += "    set default-action reject\n"
            config += "    set enable-default-log\n"

            for rule_name in fw_rules[zone]:
                rule = getattr(self, rule_name)
                config += "    edit rule {0}\n".format(rule['number'])

                for option, value in rule.iteritems():
                    if option != 'number':
                        config += self._generate_sub_config(option, value)

                config += "        up\n"

            config += "    top\n"

        return config
            

class NATRules(RuleManager):
    """Holds all NAT rules and can print a breif view or full config"""

    def __init__(self, all_configs):
        """Load all NAT rules"""

        super(RuleManager, self).__init__()        
        self.rules = { 'source': {}, 'destination': {} }

        for config in all_configs:
            for rule_type in self.rules:
                try:
                    for rule_number, rule_data in config['NATRules'][rule_type].iteritems():
                        self.rules[rule_type][rule_number] = rule_data
                        setattr(self, "{0}_{1}".format(rule_type, rule_number), rule_data)
                    
                except (AttributeError, KeyError, TypeError):
                    pass

    def __str__(self):
        """Returns a str() of all NAT rules and their description"""
        
        config = ''
        for nat_type in self.rules:
            config += "{0} nat's:\n".format(nat_type)
            for nat_number in self.rules[nat_type]:
                desc = self.rules[nat_type][nat_number].get('description', 'No Description Available')
                config += "    {0}: {1}\n".format(nat_number, desc)
            config += '\n'

        return config


    def config(self, rule_type, rule_number, brief=False):
        """Returns a str() of either a brief view or full config for a NAT rule"""

        config = ''
        if brief:
            description = self.rules[rule_type][rule_number]['description']
            config += "   {0}: {1}\n".format(rule_number, description)
        
        else:
            config += "edit nat {0} rule {1}\n".format(rule_type, rule_number)
            for option, value in self.rules[rule_type][rule_number].iteritems():
                config += self._generate_sub_config(option, value)

            config += "        top\n"

        return config


class FirewallHost(object):
    """Holds all information needed to generate a firewall config"""

    def __init__(self, config_file):
        """Load all information for the firewall"""

        self._zones = []
        self._zone_interfaces = {}
        self._address_groups = []
        self._network_groups = []
        self._port_groups = []
        self._rules = {}
        self._self_filter_outbound = None

        all_configs = [self._load_config(config_file)]

        try:
            for role_config_file in all_configs[0]['IncludeConfigs']:
                all_configs.insert(0, self._load_config(role_config_file))
        except (AttributeError, KeyError, TypeError):
            pass

        self._yaml_address_groups = GroupManager('address', all_configs)
        self._yaml_network_groups = GroupManager('network', all_configs)
        self._yaml_port_groups = GroupManager('port', all_configs)
        self._yaml_rule_templates = RuleTemplates(all_configs)
        self._yaml_nat_rules = NATRules(all_configs)

        self._prepare_zones(all_configs)
        self._find_yaml_firewall_rules(all_configs)


    def __iter__(self):
        """Returns an iter() of all zone-pairs"""
        return iter(self._rules)


    def _load_config(self, config_file):
        """Returns a dict() created from a YAML config file"""

        try:
            return yaml.safe_load(open(config_file))
        except IOError, e:
            try:
                if e.errno == 2:
                    raise ErrorConfigFileDoesNotExist(config_file)
            except Exception:
                raise


    def _prepare_zones(self, configs):
        """Load zones, verifies they have an interface assigned and generate zone-pairs"""

        for config in configs:
            try:
                for zone in config['Zones']:
                    self._add_zone(zone)
            
            except (AttributeError, KeyError, TypeError):
                pass

        if not self._zones:
            raise ErrorHostHasNoZonesDefined()

        self._prepare_zone_policy(configs)
        self._add_zone('Self')

        for src, dst in itertools.permutations(self._zones, 2):
            if self._filter_outbound(src):
                zone = "{0}-To-{1}".format(src, dst)
                self._rules[zone] = []


    def _add_zone(self, zone):
        """Add a zone to this firewall preventing duplicate inserts"""

        if not zone in self._zones:
            self._zones.append(zone)
            self._zone_interfaces[zone] = []


    def _prepare_zone_policy(self, configs):
        """Validate required zone policy information is available and assoicate zones with interfaces"""

        filter_outbound = None
        for config in configs:
            try:
                filter_outbound = config['ZonePolicy']['FilterSelfOutbound']
            except (AttributeError, KeyError, TypeError):
                pass

        if filter_outbound is None:
            raise ErrorNotDefinedSelfOutboundPolicy()
        else:
            self._self_filter_outbound = filter_outbound

        for config in configs:
            for zone in self._zones:
                try:
                    for interface in config['ZonePolicy']['Interfaces'][zone]:
                        if not interface in self._zone_interfaces[zone]:
                            self._zone_interfaces[zone].append(interface)
                except (AttributeError, KeyError, TypeError):
                    pass

        for zone in self._zones:
            if not self._zone_interfaces[zone]:
                raise ErrorZoneHasNoInterfaces(zone)


    def _find_yaml_firewall_rules(self, configs):
        """Find all firewall rules and associate them with zone-pairs"""

        unsafe_zones = []
        for config in configs:
            try:
                unsafe_zones += config.get('UnsafeZones', [])
            except (AttributeError, KeyError, TypeError):
                pass

        for config in configs:
            for zone_pair in self:
                # Check for rules from zones classes and zone pairs
                for zone_type in self._zone_types():
                    if self._process_zone(zone_type, zone_pair, unsafe_zones):
                        try:
                            for rule_name in config['FirewallRules'][zone_type]:
                                self.add_rule(zone_pair, rule_name)
                        except (AttributeError, KeyError, TypeError):
                            pass


    def _zone_types(self):
        """
        Returns a list() of all zone-types built from the key names of the FirewallRules: tree from the YAML configs
        
        Additionally generates and adds dynamic zone-types to the list
        """
        
        rule_types = ['ALL_ZONES', 'SAFE_ZONES', 'UNSAFE_ZONES']
        rule_types += self._rules.keys()

        for zone in self._zones:
            rule_types.append(zone)
            rule_types.append("TO_{0}".format(zone))
            rule_types.append("FROM_{0}".format(zone))

        return rule_types


    def _process_zone(self, zone_type, zone_pair, unsafe_zones):
        """Returns a bool() indicating if the rules from a zone-type should be added to a zone-pair"""

        result = False
        neither_zone_restricted = self._neither_zone_is_restricted(zone_pair, unsafe_zones)

        if zone_type == 'ALL_ZONES':
            result = True

        elif zone_type == 'SAFE_ZONES':
            result = neither_zone_restricted

        elif zone_type == 'UNSAFE_ZONES':
            result = not neither_zone_restricted

        elif zone_type.startswith('TO_') or zone_type.startswith('FROM_') or zone_type in self._zones:
            result = self._dynamic_class_match(zone_pair, zone_type, unsafe_zones)

        else:
            result = True if zone_pair == zone_type else False

        return result


    def _neither_zone_is_restricted(self, zone_pair, unsafe_zones):
        """Returns a bool() indicating if neither zone in a zone pair is in the UnsafeZones list"""

        result = True
        for zone in zone_pair.split('-To-'):
            if zone in unsafe_zones:
                result = False

        return result


    def _dynamic_class_match(self, zone_pair, zone_type, unsafe_zones):
        """Returns a bool() indicating if rules from a dynamic zone-type should be added to a zone-pair"""
        
        zone = ''
        direction = ''
        result = False
        dynamic_unsafe_zones = list(unsafe_zones)

        if zone_type.startswith('TO_'):
            zone = zone_type[3:]
            direction = 'destination'
        elif zone_type.startswith('FROM_'):
            zone = zone_type[5:]
            direction = 'source'
        else:
            zone = zone_type

        if zone in unsafe_zones:
            dynamic_unsafe_zones.remove(zone)
        
        if self._neither_zone_is_restricted(zone_pair, dynamic_unsafe_zones):
            if direction:
                result = self._zone_match(zone_pair, zone, direction)
            else:
                result = True if zone_type in zone_pair else False

        return result


    def _zone_match(self, zone_pair, zone, match):
        """Returns a bool() indicating if a zone is part of a zone-pair"""
        
        result = False
        action_map = {  'destination': zone_pair.endswith,
                        'source': zone_pair.startswith}
        return action_map[match](zone)


    def add_rule(self, zone, rule):
        """Add a rule to this firewall"""

        try:
            if not rule in self._rules[zone]:
                self._rules[zone].append(rule)
        
        except KeyError:
            raise ErrorZoneNotDefined(zone)


    def config(self, brief=False):
        """Returns a str() of either the bref view or full config of the entire firewall"""

        self._define_groups()
        config = self._generic_settings(brief)
        config += self._generate_group_config('address', brief)
        config += self._generate_group_config('network', brief)
        config += self._generate_group_config('port', brief)
        config += self._generate_firewall_config(brief)
        config += self._zone_policy(brief)
        config += self._generate_nat_rules(brief)
        
        return config


    def _define_groups(self):
        """
        Dynamically find all Address/Network/Port groups used by this firewall
        
        Loop through all FirewallRules: and fine where either 'source' or 'destination' options are used, if found pass them on for further processing
        """

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

        self._address_groups.sort()
        self._network_groups.sort()
        self._port_groups.sort()


    def _find_group_in_rule(self, option):
        """Look for groups used in source or destionation options, find any groups and add them to the required list"""

        try:
            option_tree, group_type, group_name = option.split(' ')

            if option_tree == 'group':
                group_type_map = {  'address-group': self._address_groups,
                                    'network-group': self._network_groups,
                                    'port-group': self._port_groups}
                
                if not group_name in group_type_map[group_type]:
                    group_type_map[group_type].append(group_name)

        except ValueError:
            pass


    def _generic_settings(self, brief):
        """
        Returns a str() of either a brief view or full config of generic firewall options
        
        TODO: Define these rules in the YAML config instead of hard-coding them here
        """

        config = self._generate_large_msg('Generic Firewall Settings')
        firewall_options = {'all-ping': 'enable',
                            'broadcast-ping': 'disable',
                            'ip-src-route': 'disable',
                            'ipv6-receive-redirects': 'disable',
                            'ipv6-src-route': 'disable',
                            'log-martians': 'disable',
                            'receive-redirects': 'disable',
                            'send-redirects': 'enable',
                            'source-validation': 'disable',
                            'syn-cookies': 'enable',
                            }

        
        if brief:
            for option, value in firewall_options.iteritems():
                config += "{0}: {1}\n".format(option, value)
        else:
            config += "edit firewall\n"
            for option, value in firewall_options.iteritems():
                config += "   delete {0}\n".format(option)
                config += "   set {0} {1}\n".format(option, value)
            config += "   top\n"

        return config


    def _generate_group_config(self, group_type, brief=False):
        """Returns a str() of either the brief view or full config for a group type"""

        config_map = {  'names':    {'address': self._address_groups,
                                     'network': self._network_groups,
                                     'port': self._port_groups},

                        'yaml':     {'address': self._yaml_address_groups,
                                     'network': self._yaml_network_groups,
                                     'port': self._yaml_port_groups},
                    }

        config = self._generate_large_msg("{0} Groups".format(group_type))

        if not brief:
            config += self._generate_small_msg("Delete all {0} groups".format(group_type))
            config += "delete firewall group {0}-group\n".format(group_type)

        for group in config_map['names'][group_type]:
            config += self._generate_small_msg("GROUP: {0}".format(group))
            config += config_map['yaml'][group_type].config(group, brief)

        return config

    def _generate_firewall_config(self, brief=False):
        """Returns a str() of either a brief view or full config for firewall rules"""

        config = self._generate_large_msg('Firewall Rules')

        if not brief:
            config += self._generate_small_msg('Delete all firewalls')
            config += 'delete firewall name'
            config += self._generate_small_msg('Firewall: ALLOW-ALL')
            config += "set firewall name ALLOW-ALL default-action accept\n"

        for zone in self._rules:
            config += self._generate_small_msg("Firewall: {0}".format(zone))
            config += self._yaml_rule_templates.config(zone, self._rules, brief)

        return config


    def _generate_nat_rules(self, brief=False):
        """Returns a str() of either a brief view or full config for NAT rules"""

        config = self._generate_large_msg('NAT Rules')

        if not brief:
            config += self._generate_small_msg('Delete all NAT rules')
            config += "delete nat\n"

        for rule_type in self._yaml_nat_rules:
            config += self._generate_small_msg("{0} Rules".format(rule_type))

            for rule_number in sorted(self._yaml_nat_rules.rules[rule_type]):
                config += self._yaml_nat_rules.config(rule_type, rule_number, brief)

        return config


    def _zone_policy(self, brief=False):
        """Returns a str() of either a breief view or full config of the ZonePolicy"""

        config = self._generate_large_msg('Zone Policies')

        if not brief:
            config += self._generate_small_msg('Delete zone policy')
            config += "delete zone-policy\n"

        if brief:
            for dst in self._zones:
                config += self._generate_small_msg("ZONE: {0}".format(dst))
                for src in self._zones:
                    fw_name = "{0}-To-{1}".format(src, dst) if self._filter_outbound(src) else 'ALLOW-ALL'
                    config += "    From Zone {0} Apply Firewall {1}\n".format(src, fw_name)
                config += '\n'

        else:
            for dst in self._zones:
                config += self._generate_small_msg("ZONE: {0}".format(dst))
                config += "edit zone-policy zone {0}\n".format(dst)
                config += "    set default-action reject\n"
                for interface in self._zone_interfaces[dst]:
                    config += "    set interface {0}\n".format(interface)

                for src in self._zones:
                    if dst != src:
                        fw_name = "{0}-To-{1}".format(src, dst) if self._filter_outbound(src) else 'ALLOW-ALL'
                        config += "    set from {0} firewall name {1}\n".format(src, fw_name)
    
                if dst == 'Self':
                    config += '    set local-zone\n'
    
                config += '    top\n'

        return config


    def _filter_outbound(self, zone):
        """Returns a bool() indicating if a zone requires outbound filtering"""
        
        result = True
        if zone == 'Self' and not self._self_filter_outbound:
            result = False
        return result
    

    @staticmethod
    def _generate_large_msg(msg):
        return """
    ############################################
    ############################################
    ###
    ###     {0}
    ###
    ############################################
    ############################################
    
    """.format(msg)
    
    
    @staticmethod
    def _generate_small_msg(msg):
        return "\n# {0}\n".format(msg)


