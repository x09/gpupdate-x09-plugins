#
# Tests for the x09_firewall gpupdate plugin.
#
# Copyright (C) 2025 x09.
#
# These tests cover the pure functions of the plugin (rule parsing,
# iptables argument building, registry extraction). They mock gpoa_lib so
# the module can be imported without the full gpupdate stack installed.

import importlib.util
import os
import sys
import types

import pytest


def _load_module():
    """Import plugin/x09_firewall.py with gpoa_lib mocked out."""
    if 'gpoa_lib' not in sys.modules:
        gpoa_lib = types.ModuleType('gpoa_lib')
        plugin_mod = types.ModuleType('gpoa_lib.plugin')
        plugin_base = types.ModuleType('gpoa_lib.plugin.plugin_base')

        class FrontendPlugin:
            def __init__(self, *a, **k):
                self._registry_path = a[3] if len(a) > 3 else k.get('registry_path')
                self.username = a[1] if len(a) > 1 else k.get('username')

            def _init_plugin_log(self, *a, **k):
                pass

            def log(self, *a, **k):
                pass

            def get_dict_registry(self, *a, **k):
                return {}

        plugin_base.FrontendPlugin = FrontendPlugin
        plugin_mod.plugin_base = plugin_base
        gpoa_lib.plugin = plugin_mod
        sys.modules['gpoa_lib'] = gpoa_lib
        sys.modules['gpoa_lib.plugin'] = plugin_mod
        sys.modules['gpoa_lib.plugin.plugin_base'] = plugin_base

    plugin_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'plugin', 'x09_firewall.py')
    spec = importlib.util.spec_from_file_location('x09_firewall', plugin_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fw = _load_module()


# --------------------------------------------------------------------------- #
# parse_rule — валидные
# --------------------------------------------------------------------------- #

def test_parse_full_rule():
    r = fw.parse_rule(
        "Action=Allow;Direction=In;Protocol=TCP;Port=80;"
        "Source=10.0.0.0/24;Destination=192.168.1.1")
    assert r == {
        'action': 'allow', 'direction': 'in', 'protocol': 'tcp',
        'port': '80', 'source': '10.0.0.0/24', 'destination': '192.168.1.1',
    }


def test_parse_case_and_order_insensitive():
    r = fw.parse_rule("protocol=udp;ACTION=Deny;direction=OUT;port=53")
    assert r == {'action': 'deny', 'direction': 'out',
                 'protocol': 'udp', 'port': '53'}


def test_parse_minimal():
    r = fw.parse_rule("Action=Reject;Direction=In;Protocol=TCP")
    assert r == {'action': 'reject', 'direction': 'in', 'protocol': 'tcp'}


def test_parse_empty_optional_fields_ignored():
    r = fw.parse_rule("Action=Allow;Direction=In;Protocol=TCP;Source=;Destination=")
    assert 'source' not in r and 'destination' not in r


def test_parse_port_range():
    r = fw.parse_rule("Action=Deny;Direction=Out;Protocol=TCP;Port=53-153")
    assert r['port'] == '53-153'
    assert r['multiport'] is True


def test_parse_port_list():
    r = fw.parse_rule("Action=Allow;Direction=In;Protocol=UDP;Port=22,80,443")
    assert r['port'] == '22,80,443'
    assert r['multiport'] is True


def test_parse_single_port_no_multiport():
    r = fw.parse_rule("Action=Allow;Direction=In;Protocol=TCP;Port=80")
    assert r['port'] == '80'
    assert 'multiport' not in r


# --------------------------------------------------------------------------- #
# parse_rule — невалидные
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw", [
    "Action=Foo;Direction=In;Protocol=TCP",
    "Action=Allow;Direction=Sideways;Protocol=TCP",
    "Action=Allow;Direction=In;Protocol=ICMP",
    "Action=Allow;Direction=In",
    "Action=Allow;Direction=In;Protocol=TCP;Port=abc",
    "Action=Allow;Direction=In;Protocol=TCP;Port=70000",
    "Action=Allow;Direction=In;Protocol=TCP;Port=0",
    "Action=Allow;Direction=In;Protocol=TCP;Source=999.1.1.1",
    "Action=Allow;DirectionIn;Protocol=TCP",
    "Action=Allow;Direction=In;Protocol=TCP;Port=100-50",  # start > end
    "Action=Allow;Direction=In;Protocol=TCP;Port=80,abc",  # невалидный порт в списке
    "Action=Allow;Direction=In;Protocol=TCP;Port=22,70000", # порт вне диапазона в списке
    "",
])
def test_parse_invalid_raises(raw):
    with pytest.raises(fw.RuleError):
        fw.parse_rule(raw)


# --------------------------------------------------------------------------- #
# build_iptables_args
# --------------------------------------------------------------------------- #

def test_build_full():
    r = fw.parse_rule(
        "Action=Allow;Direction=In;Protocol=TCP;Port=80;"
        "Source=10.0.0.0/24;Destination=192.168.1.1")
    assert fw.build_iptables_args(r) == [
        '-A', 'FW_PLUGIN_INPUT', '-p', 'tcp', '-s', '10.0.0.0/24',
        '-d', '192.168.1.1', '--dport', '80', '-j', 'ACCEPT']


def test_build_out_deny():
    r = fw.parse_rule("Action=Deny;Direction=Out;Protocol=UDP;Port=53")
    assert fw.build_iptables_args(r) == [
        '-A', 'FW_PLUGIN_OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'DROP']


def test_build_reject_minimal():
    r = fw.parse_rule("Action=Reject;Direction=In;Protocol=TCP")
    assert fw.build_iptables_args(r) == [
        '-A', 'FW_PLUGIN_INPUT', '-p', 'tcp', '-j', 'REJECT']


def test_build_no_destination():
    r = fw.parse_rule("Action=Deny;Direction=Out;Protocol=TCP;Port=443;Source=10.0.0.0/24")
    assert fw.build_iptables_args(r) == [
        '-A', 'FW_PLUGIN_OUTPUT', '-p', 'tcp', '-s', '10.0.0.0/24', '--dport', '443', '-j', 'DROP']


def test_build_no_source():
    r = fw.parse_rule("Action=Allow;Direction=In;Protocol=UDP;Port=53;Destination=8.8.8.8")
    assert fw.build_iptables_args(r) == [
        '-A', 'FW_PLUGIN_INPUT', '-p', 'udp', '-d', '8.8.8.8', '--dport', '53', '-j', 'ACCEPT']


def test_build_no_source_no_destination():
    r = fw.parse_rule("Action=Deny;Direction=Out;Protocol=TCP;Port=22")
    assert fw.build_iptables_args(r) == [
        '-A', 'FW_PLUGIN_OUTPUT', '-p', 'tcp', '--dport', '22', '-j', 'DROP']


def test_build_port_range_multiport():
    r = fw.parse_rule("Action=Deny;Direction=Out;Protocol=TCP;Port=53-153;Destination=8.8.8.8")
    assert fw.build_iptables_args(r) == [
        '-A', 'FW_PLUGIN_OUTPUT', '-p', 'tcp', '-d', '8.8.8.8',
        '-m', 'multiport', '--dports', '53-153', '-j', 'DROP']


def test_build_port_list_multiport():
    r = fw.parse_rule("Action=Allow;Direction=In;Protocol=TCP;Port=22,80,443")
    assert fw.build_iptables_args(r) == [
        '-A', 'FW_PLUGIN_INPUT', '-p', 'tcp',
        '-m', 'multiport', '--dports', '22,80,443', '-j', 'ACCEPT']


# --------------------------------------------------------------------------- #
# extract_rule_lines
# --------------------------------------------------------------------------- #

def test_extract_flat_order_and_marker():
    flat = {'Rule2': 'b', 'Rule10': 'j', 'Rule1': 'a', 'RulesList': '1'}
    assert fw.extract_rule_lines(flat) == ['a', 'b', 'j']


def test_extract_nested():
    nested = {'Software/Policies/x09/Firewall':
              {'Rule1': 'x', 'Rule2': 'y', 'RulesList': '1'}}
    assert fw.extract_rule_lines(nested) == ['x', 'y']


def test_extract_pathed_flat():
    pathed = {'Software/Policies/x09/Firewall/Rule1': 'p',
              'Software/Policies/x09/Firewall/RulesList': '1'}
    assert fw.extract_rule_lines(pathed) == ['p']


def test_extract_empty():
    assert fw.extract_rule_lines({}) == []
    assert fw.extract_rule_lines(None) == []
