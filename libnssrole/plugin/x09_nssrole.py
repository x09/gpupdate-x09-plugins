#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2026 x09
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.

"""
libnss-role management plugin for gpupdate.

This plugin reads role definitions from Group Policy and writes them
to /etc/role.d/ for libnss-role to apply.
"""

import os
import logging
import re

from gpoa_lib.plugin.plugin_base import FrontendPlugin

# Logging
log = logging.getLogger('plugin.x09_nssrole')

# Registry path (use forward slashes for gpoa compatibility)
REGISTRY_PATH = 'Software/Policies/x09/LibnssRole'

# Prefix for list values (from ADMX valuePrefix attribute, default is "Role")
ROLE_PREFIX = 'Role'

# Marker value to skip (from ADMX list element id)
MARKER_VALUE = 'RolesList'

# Role directory and default filename
ROLE_DIR = '/etc/role.d'
DEFAULT_FILENAME = 'custom-roles.role'

# Regex pattern to validate role line format: group:group1,group2,...
# Allows: Latin, Cyrillic letters, digits, space, backslash, hyphen, underscore
# Pattern explicitly lists allowed characters (including Cyrillic ranges)
ROLE_LINE_PATTERN = re.compile(
    r'^[a-zA-Zа-яА-ЯёЁ0-9\\\s\-_]+:[a-zA-Zа-яА-ЯёЁ0-9\\\s\-_,]+$'
)


def extract_role_lines(config):
    """
    Extract role definition lines from registry data.

    The ADMX list element stores data as a Python list in string format:
    "['role1: groups', 'role2: groups']"

    This function parses that string representation back into a list.

    :param config: dictionary from registry
    :returns: list of role definition strings
    """
    if not config:
        return []

    # The data might be stored directly under the registry path key
    # or in a nested structure. We need to find the list value.

    # First, try to get the value directly if config is a simple dict
    if isinstance(config, str):
        # If config is already a string (rare case), parse it
        try:
            import ast
            roles = ast.literal_eval(config)
            if isinstance(roles, list):
                return [str(r).strip() for r in roles]
        except:
            return []

    # Look for the LibnssRole key in various possible locations
    def find_list_value(data):
        """Recursively search for the list value in nested dict"""
        if isinstance(data, str):
            # Try to parse as Python list
            try:
                import ast
                parsed = ast.literal_eval(data)
                if isinstance(parsed, list):
                    return parsed
            except:
                pass
            return None
        elif isinstance(data, list):
            return data
        elif isinstance(data, dict):
            # Check direct keys first
            for key in ['LibnssRole', 'libnssrole']:
                if key in data:
                    result = find_list_value(data[key])
                    if result:
                        return result
            # Recursively check all values
            for value in data.values():
                result = find_list_value(value)
                if result:
                    return result
        return None

    roles_list = find_list_value(config)

    if roles_list and isinstance(roles_list, list):
        return [str(r).strip() for r in roles_list]

    return []


class X09NssRoleApplier(FrontendPlugin):
    """
    Applies libnss-role configuration from Group Policy.
    """

    # Domain for translations
    domain = 'x09_nssrole'

    def __init__(self, dict_dconf_db, username=None, fs_file_cache=None, registry_path=None):
        super().__init__(dict_dconf_db, username, fs_file_cache, registry_path)
        self._registry_path = registry_path
        self.roles = []
        self.filename = DEFAULT_FILENAME

        # Initialize plugin logging (without translations to avoid encoding issues)
        self._init_plugin_log(
            message_dict={
                'i': {
                    0: "Starting libnss-role applier",
                    1: "No libnss-role policy found in registry",
                    2: "Using custom role filename: {filename}",
                    3: "Read {count} role definitions from policy",
                    4: "No roles to write, skipping",
                    5: "Created role directory: {dir}",
                    6: "Successfully wrote {count} roles to {file}",
                    7: "libnss-role applier completed successfully",
                },
                'w': {
                    1: "Invalid filename '{filename}', using default: {default}",
                    2: "Invalid role line (missing or multiple colons): {line}",
                    3: "Invalid role line format: {line}",
                    4: "Invalid role line (empty role name): {line}",
                    5: "Invalid role line (empty group list): {line}",
                    6: "Skipping invalid role line: {line}",
                    7: "No valid role definitions found after validation",
                },
                'e': {
                    1: "Failed to create role directory {dir}: {error}",
                    2: "Failed to write role file {file}: {error}",
                    3: "libnss-role applier failed: {error}",
                },
            },
            domain=None,  # Disable translations
        )

    def _read_policy(self):
        """
        Read role definitions from registry.

        The data is stored as:
        Software/Policies/x09/LibnssRole = "['role1: groups', 'role2: groups']"
        Software/Policies/x09/LibnssRole/Settings/RoleFileName = "filename.role"
        """
        # Get all data from the registry path
        policy_data = self.get_dict_registry(self._registry_path or REGISTRY_PATH)

        # If get_dict_registry returns empty, try direct entry access
        if not policy_data:
            from gpoa_lib import StorageAdapter
            try:
                adapter = StorageAdapter.from_dconf_db('policy')
                direct_value = adapter.get_entry(REGISTRY_PATH, preg=False)

                # If direct entry has value, use it
                if direct_value:
                    # Parse the list directly
                    self.roles = extract_role_lines(direct_value)
                    if self.roles:
                        self.log('I3', {'count': len(self.roles)})
                    # Mark that we have data to continue reading Settings
                    policy_data = {'_from_direct': True}
            except Exception as e:
                log.warning("Could not read policy via direct entry: %s", e)

        if not policy_data:
            self.log('I1')  # No policy found
            return

        # Extract role lines from the list stored in LibnssRole key (if not already done)
        if not self.roles:
            self.roles = extract_role_lines(policy_data)
            if self.roles:
                self.log('I3', {'count': len(self.roles)})

        # Read filename from Settings subkey
        settings_path = (self._registry_path or REGISTRY_PATH) + '/Settings'
        settings_data = self.get_dict_registry(settings_path)

        if settings_data:
            # Extract RoleFileName value, handling both flat and nested formats
            filename = None
            if 'RoleFileName' in settings_data:
                filename = settings_data['RoleFileName']
            else:
                # Check nested format (dict values)
                for key, value in settings_data.items():
                    if isinstance(value, dict) and 'RoleFileName' in value:
                        filename = value['RoleFileName']
                        break
                    elif key.endswith('RoleFileName'):
                        filename = value
                        break

            if filename:
                filename = str(filename).strip().rstrip('\x00')
                if filename and self._validate_filename(filename):
                    self.filename = filename
                    self.log('I2', {'filename': self.filename})
                else:
                    self.log('W1', {'filename': filename, 'default': DEFAULT_FILENAME})
        # If RoleFileName is not set, self.filename already has DEFAULT_FILENAME

    def _validate_filename(self, filename):
        """
        Validate role filename: only ASCII alphanumerics, hyphen, underscore, dot.
        No path separators, no special characters.

        Args:
            filename: Filename to validate

        Returns:
            bool: True if valid
        """
        # Must end with .role
        if not filename.endswith('.role'):
            return False

        # Only allow safe characters: a-zA-Z0-9_-.
        if not re.match(r'^[a-zA-Z0-9_\-]+\.role$', filename):
            return False

        # No path separators
        if '/' in filename or '\\' in filename:
            return False

        return True

    def _validate_role_line(self, line):
        """
        Validate a single role definition line.

        Expected format: <group>:<group>[,<group>]*

        Допускает символы: латиница, кириллица, \\, -, _, пробелы

        Args:
            line: Role definition line

        Returns:
            bool: True if valid
        """
        if not line:
            return False

        # Must contain exactly one colon
        if line.count(':') != 1:
            self.log('W2', {'line': line})
            return False

        # Check against pattern
        if not ROLE_LINE_PATTERN.match(line):
            self.log('W3', {'line': line})
            return False

        # Split and validate parts
        left, right = line.split(':', 1)

        if not left.strip():
            self.log('W4', {'line': line})
            return False

        if not right.strip():
            self.log('W5', {'line': line})
            return False

        return True

    def _write_role_file(self):
        """
        Write role definitions to /etc/role.d/ file.
        """
        if not self.roles:
            self.log('I4')  # No roles to write
            return

        # Validate all role lines
        valid_roles = []
        for role_line in self.roles:
            if self._validate_role_line(role_line):
                valid_roles.append(role_line)
            else:
                self.log('W6', {'line': role_line})

        if not valid_roles:
            self.log('W7')  # No valid roles after validation
            return

        # Ensure role directory exists
        if not os.path.exists(ROLE_DIR):
            try:
                os.makedirs(ROLE_DIR, mode=0o755)
                self.log('I5', {'dir': ROLE_DIR})
            except OSError as exc:
                self.log('E1', {'dir': ROLE_DIR, 'error': str(exc)})
                raise

        # Write role file (overwrite strategy)
        filepath = os.path.join(ROLE_DIR, self.filename)
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for role_line in valid_roles:
                    f.write(role_line + '\n')

            # Set proper permissions (readable by all)
            os.chmod(filepath, 0o644)

            self.log('I6', {'count': len(valid_roles), 'file': filepath})

        except (OSError, IOError) as exc:
            self.log('E2', {'file': filepath, 'error': str(exc)})
            raise

    def run(self, **kwargs):
        """
        Main entry point: read policy and apply roles.

        Args:
            **kwargs: Additional arguments (not used, but required by interface)

        Returns:
            bool: True on success, False on failure
        """
        self.log('I0')  # Starting

        try:
            self._read_policy()
            self._write_role_file()
            self.log('I7')  # Completed successfully
            return True
        except Exception as exc:
            self.log('E3', {'error': str(exc)})
            return False


# --------------------------------------------------------------------------- #
# Factory function
# --------------------------------------------------------------------------- #

def create_machine_applier(dict_dconf_db, username=None, fs_file_cache=None,
                           registry_path=None):
    """
    Create an instance of the plugin for machine context.

    User factory (create_user_applier) is intentionally not defined:
    libnss-role is managed only in machine context. Plugin manager
    won't run the plugin in user context without create_user_applier.
    """
    return X09NssRoleApplier(dict_dconf_db, username, fs_file_cache,
                             registry_path)
