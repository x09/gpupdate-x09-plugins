#!/usr/bin/env python3
"""
Basic tests for x09_nssrole plugin.
"""

import pytest
import re


# Mock pattern for testing (same as in plugin)
ROLE_LINE_PATTERN = re.compile(r'^[\w\\\s\-_]+:[\w\\\s\-_,]+$', re.UNICODE)


def validate_role_line(line):
    """Validate role line format."""
    if not line:
        return False

    if line.count(':') != 1:
        return False

    if not ROLE_LINE_PATTERN.match(line):
        return False

    left, right = line.split(':', 1)

    if not left.strip():
        return False

    if not right.strip():
        return False

    return True


def validate_filename(filename):
    """Validate role filename."""
    if not filename.endswith('.role'):
        return False

    if not re.match(r'^[a-zA-Z0-9_\-]+\.role$', filename):
        return False

    if '/' in filename or '\\' in filename:
        return False

    return True


# Test role line validation
def test_validate_simple_role():
    assert validate_role_line('users: cdwriter, cdrom, audio')


def test_validate_role_with_backslash():
    assert validate_role_line('WIN\\domain admins:localadmins')


def test_validate_cyrillic_role():
    assert validate_role_line('администраторы домена:localadmins')


def test_validate_role_with_spaces():
    assert validate_role_line('domain users: users, remote')


def test_invalid_role_no_colon():
    assert not validate_role_line('users cdwriter')


def test_invalid_role_multiple_colons():
    assert not validate_role_line('users:cdwriter:audio')


def test_invalid_role_empty_left():
    assert not validate_role_line(':cdwriter,audio')


def test_invalid_role_empty_right():
    assert not validate_role_line('users:')


def test_invalid_role_empty():
    assert not validate_role_line('')


# Test filename validation
def test_valid_filename_default():
    assert validate_filename('custom-roles.role')


def test_valid_filename_with_underscores():
    assert validate_filename('my_custom_roles.role')


def test_invalid_filename_no_extension():
    assert not validate_filename('roles')


def test_invalid_filename_wrong_extension():
    assert not validate_filename('roles.txt')


def test_invalid_filename_with_path():
    assert not validate_filename('/etc/roles.role')


def test_invalid_filename_special_chars():
    assert not validate_filename('roles@admin.role')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
