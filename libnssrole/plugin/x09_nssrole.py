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
import gettext
import re

from plugin_interface import FrontendPlugin, plugin_factory
from util.paths import get_dict_registry
from util.runcmd import runcmd

# Setup gettext localization
gettext.bindtextdomain('x09_nssrole', '/usr/share/locale')
gettext.textdomain('x09_nssrole')
_ = gettext.gettext

logger = logging.getLogger('x09_nssrole')


class NssRoleApplier:
    """
    Applies libnss-role configuration from Group Policy.
    """

    ROLE_DIR = '/etc/role.d'
    DEFAULT_FILENAME = 'custom-roles.role'
    REGISTRY_PATH = 'Software\\Policies\\x09\\LibnssRole'

    # Regex pattern to validate role line format: group:group1,group2,...
    # Allows: alphanumeric, Cyrillic, space, backslash, hyphen, underscore
    ROLE_LINE_PATTERN = re.compile(r'^[\w\\\s\-_]+:[\w\\\s\-_,]+$', re.UNICODE)

    def __init__(self, storage):
        """
        Initialize the applier.

        Args:
            storage: Registry storage backend
        """
        self.storage = storage
        self.roles = []
        self.filename = self.DEFAULT_FILENAME

    def _read_policy(self):
        """
        Read role definitions from registry.
        """
        try:
            policy_data = get_dict_registry(self.storage, self.REGISTRY_PATH)

            if not policy_data:
                logger.info(_('No libnss-role policy found in registry'))
                return

            # Read custom filename if provided
            if 'RoleFileName' in policy_data:
                filename = policy_data['RoleFileName'].strip()
                if filename and self._validate_filename(filename):
                    self.filename = filename
                    logger.info(_('Using custom role filename: %s'), self.filename)
                else:
                    logger.warning(_('Invalid filename "%s", using default: %s'),
                                 filename, self.DEFAULT_FILENAME)

            # Read role definitions (Role1, Role2, ...)
            role_entries = []
            for key, value in policy_data.items():
                if key.startswith('Role') and key[4:].isdigit():
                    role_entries.append((int(key[4:]), value))

            # Sort by numeric suffix to preserve order
            role_entries.sort(key=lambda x: x[0])
            self.roles = [value.strip() for _, value in role_entries if value.strip()]

            logger.info(_('Read %d role definitions from policy'), len(self.roles))

        except Exception as exc:
            logger.error(_('Failed to read libnss-role policy: %s'), exc)
            raise

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

        Args:
            line: Role definition line

        Returns:
            bool: True if valid
        """
        if not line:
            return False

        # Must contain exactly one colon
        if line.count(':') != 1:
            logger.warning(_('Invalid role line (missing or multiple colons): %s'), line)
            return False

        # Check against pattern
        if not self.ROLE_LINE_PATTERN.match(line):
            logger.warning(_('Invalid role line format: %s'), line)
            return False

        # Split and validate parts
        left, right = line.split(':', 1)

        if not left.strip():
            logger.warning(_('Invalid role line (empty role name): %s'), line)
            return False

        if not right.strip():
            logger.warning(_('Invalid role line (empty group list): %s'), line)
            return False

        return True

    def _write_role_file(self):
        """
        Write role definitions to /etc/role.d/ file.
        """
        if not self.roles:
            logger.info(_('No roles to write, skipping'))
            return

        # Validate all role lines
        valid_roles = []
        for role_line in self.roles:
            if self._validate_role_line(role_line):
                valid_roles.append(role_line)
            else:
                logger.warning(_('Skipping invalid role line: %s'), role_line)

        if not valid_roles:
            logger.warning(_('No valid role definitions found after validation'))
            return

        # Ensure role directory exists
        if not os.path.exists(self.ROLE_DIR):
            try:
                os.makedirs(self.ROLE_DIR, mode=0o755)
                logger.info(_('Created role directory: %s'), self.ROLE_DIR)
            except OSError as exc:
                logger.error(_('Failed to create role directory %s: %s'),
                           self.ROLE_DIR, exc)
                raise

        # Write role file (overwrite strategy)
        filepath = os.path.join(self.ROLE_DIR, self.filename)
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for role_line in valid_roles:
                    f.write(role_line + '\n')

            # Set proper permissions (readable by all)
            os.chmod(filepath, 0o644)

            logger.info(_('Successfully wrote %d roles to %s'), len(valid_roles), filepath)

        except (OSError, IOError) as exc:
            logger.error(_('Failed to write role file %s: %s'), filepath, exc)
            raise

    def run(self):
        """
        Main entry point: read policy and apply roles.
        """
        logger.info(_('Starting libnss-role applier'))

        try:
            self._read_policy()
            self._write_role_file()
            logger.info(_('libnss-role applier completed successfully'))
        except Exception as exc:
            logger.error(_('libnss-role applier failed: %s'), exc)
            # Don't raise - allow gpupdate to continue with other plugins


class NssRolePlugin(FrontendPlugin):
    """
    Frontend plugin for libnss-role management.
    """

    plugin_name = 'x09_nssrole'

    def __init__(self, plugin_manager, storage):
        """
        Initialize plugin.

        Args:
            plugin_manager: Plugin manager instance
            storage: Registry storage backend
        """
        super().__init__(plugin_manager, storage)
        self.plugin_manager = plugin_manager
        self.storage = storage

    def create_machine_applier(self):
        """
        Create machine-side applier (runs as root).

        Returns:
            NssRoleApplier instance
        """
        return NssRoleApplier(self.storage)

    def create_user_applier(self, sid):
        """
        Create user-side applier (not used for libnss-role).

        Args:
            sid: User SID

        Returns:
            None (libnss-role is machine-only)
        """
        return None


def plugin_factory(plugin_manager, storage):
    """
    Factory function to create plugin instance.

    Args:
        plugin_manager: Plugin manager instance
        storage: Registry storage backend

    Returns:
        NssRolePlugin instance
    """
    return NssRolePlugin(plugin_manager, storage)
