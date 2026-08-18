#!/usr/bin/env python3
#
# GPOA - GPO Applier for Linux
# x09 Firewall plugin
#
# Copyright (C) 2025 BaseALT Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

"""
Плагин gpupdate для управления межсетевым экраном (iptables) через
групповые политики.

Правила задаются ADMX-политикой «Управление правилами брандмауэра» и
хранятся в реестре по пути ``Software/Policies/x09/Firewall`` как значения
``Rule1``, ``Rule2`` … Каждое значение — одна строка вида::

    Action=Allow;Direction=In;Protocol=TCP;Port=80;Source=10.0.0.0/24;Destination=192.168.1.1

Поле Port может содержать одиночный порт (80), диапазон (53-153) или список (22,80,443).
При использовании диапазонов и списков автоматически применяется модуль multiport iptables.

Плагин парсит эти строки, транслирует их в правила iptables и применяет их
в выделенные пользовательские цепочки ``FW_PLUGIN_INPUT`` и
``FW_PLUGIN_OUTPUT``, которые подключаются к системным цепочкам INPUT/OUTPUT.
Такой подход не затрагивает прочие правила и не блокирует трафик по
умолчанию (в конце наших цепочек происходит неявный RETURN).
"""

import ipaddress
import re
import shutil
import subprocess

from gpoa_lib.plugin.plugin_base import FrontendPlugin


# --------------------------------------------------------------------------- #
# Константы
# --------------------------------------------------------------------------- #

#: Ветка реестра, куда ADMX-политика записывает правила.
REGISTRY_PATH = 'Software/Policies/x09/Firewall'

#: Префикс имён значений списка (см. valuePrefix в ADMX).
RULE_PREFIX = 'Rule'

#: Имя маркерного значения политики, которое нужно игнорировать.
MARKER_VALUE = 'RulesList'

#: Имена выделенных пользовательских цепочек по направлениям.
CHAINS = {
    'in': 'FW_PLUGIN_INPUT',
    'out': 'FW_PLUGIN_OUTPUT',
}

#: Системные цепочки, к которым подключаются наши цепочки.
PARENT_CHAINS = {
    'in': 'INPUT',
    'out': 'OUTPUT',
}

#: Трансляция действия правила в цель (target) iptables.
ACTION_TARGETS = {
    'allow': 'ACCEPT',
    'deny': 'DROP',
    'reject': 'REJECT',
}

VALID_PROTOCOLS = ('tcp', 'udp')

#: Путь к файлу сохранения правил (штатный механизм ALT).
IPTABLES_SAVE_PATH = '/etc/sysconfig/iptables'

#: Исполняемые файлы iptables.
IPTABLES_BIN = 'iptables'
IPTABLES_SAVE_BIN = 'iptables-save'


# --------------------------------------------------------------------------- #
# Разбор и валидация правил (уровень модуля — тестируется независимо)
# --------------------------------------------------------------------------- #

class RuleError(ValueError):
    """Строка правила некорректна и должна быть пропущена."""


def parse_rule(raw):
    """
    Разобрать одну строку правила в нормализованный словарь.

    Формат строки (регистр и порядок полей не важны)::

        Action=Allow;Direction=In;Protocol=TCP;Port=80;Source=..;Destination=..

    :param raw: исходная строка правила.
    :returns: словарь с ключами ``action``, ``direction``, ``protocol`` и
              (опционально) ``port``, ``source``, ``destination``.
    :raises RuleError: если строка не проходит валидацию.
    """
    if raw is None:
        raise RuleError('empty rule')

    text = raw.strip()
    if not text:
        raise RuleError('empty rule')

    fields = {}
    for part in text.split(';'):
        part = part.strip()
        if not part:
            continue
        if '=' not in part:
            raise RuleError("field without '=': '{0}'".format(part))
        key, value = part.split('=', 1)
        fields[key.strip().lower()] = value.strip()

    # --- обязательные поля -------------------------------------------------
    action = fields.get('action', '').lower()
    if action not in ACTION_TARGETS:
        raise RuleError("invalid or missing Action '{0}'".format(fields.get('action', '')))

    direction = fields.get('direction', '').lower()
    if direction not in CHAINS:
        raise RuleError("invalid or missing Direction '{0}'".format(fields.get('direction', '')))

    protocol = fields.get('protocol', '').lower()
    if protocol not in VALID_PROTOCOLS:
        raise RuleError("invalid or missing Protocol '{0}'".format(fields.get('protocol', '')))

    rule = {
        'action': action,
        'direction': direction,
        'protocol': protocol,
    }

    # --- необязательные поля ----------------------------------------------
    port = fields.get('port', '')
    if port:
        # Поддержка: одиночный порт (80), диапазон (53-153), список (22,80,443)
        if ',' in port or '-' in port:
            _validate_port_spec(port)
            rule['port'] = port
            rule['multiport'] = True
        else:
            if not re.fullmatch(r'\d+', port):
                raise RuleError("Port must be a number: '{0}'".format(port))
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise RuleError("Port out of range 1-65535: '{0}'".format(port))
            rule['port'] = str(port_num)

    for addr_field in ('source', 'destination'):
        value = fields.get(addr_field, '')
        if value:
            _validate_address(value, addr_field)
            rule[addr_field] = value

    return rule


def _validate_address(value, field_name):
    """Проверить, что значение — корректный IP-адрес или CIDR-сеть."""
    try:
        # strict=False допускает host-биты в записи вида 10.0.0.5/24
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise RuleError("invalid {0} address '{1}'".format(field_name, value))


def _validate_port_spec(spec):
    """
    Проверить спецификацию портов для multiport: диапазон (53-153) или список (22,80,443).

    :raises RuleError: если формат некорректен или порты вне диапазона 1-65535.
    """
    if ',' in spec:
        # Список портов
        parts = [p.strip() for p in spec.split(',')]
        for p in parts:
            if not re.fullmatch(r'\d+', p):
                raise RuleError("Invalid port in list '{0}': '{1}'".format(spec, p))
            port_num = int(p)
            if not 1 <= port_num <= 65535:
                raise RuleError("Port out of range in list '{0}': {1}".format(spec, port_num))
    elif '-' in spec:
        # Диапазон портов
        parts = spec.split('-', 1)
        if len(parts) != 2:
            raise RuleError("Invalid port range format '{0}'".format(spec))
        start_str, end_str = parts[0].strip(), parts[1].strip()
        if not re.fullmatch(r'\d+', start_str) or not re.fullmatch(r'\d+', end_str):
            raise RuleError("Invalid port range '{0}'".format(spec))
        start, end = int(start_str), int(end_str)
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise RuleError("Port range out of bounds '{0}'".format(spec))
        if start > end:
            raise RuleError("Port range start > end '{0}'".format(spec))
    else:
        raise RuleError("Port spec '{0}' has no comma or dash".format(spec))


def build_iptables_args(rule):
    """
    Построить список аргументов iptables для добавления правила в нашу цепочку.

    :param rule: нормализованный словарь из :func:`parse_rule`.
    :returns: список аргументов (без ведущего исполняемого файла), напр.
              ``['-A', 'FW_PLUGIN_INPUT', '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT']``.
    """
    chain = CHAINS[rule['direction']]
    args = ['-A', chain, '-p', rule['protocol']]

    if 'source' in rule:
        args += ['-s', rule['source']]
    if 'destination' in rule:
        args += ['-d', rule['destination']]
    if 'port' in rule:
        if rule.get('multiport'):
            # Используем multiport для диапазонов и списков
            args += ['-m', 'multiport', '--dports', rule['port']]
        else:
            args += ['--dport', rule['port']]

    args += ['-j', ACTION_TARGETS[rule['action']]]
    return args


def extract_rule_lines(config):
    """
    Извлечь строки правил из словаря реестра, полученного от
    :meth:`get_dict_registry`.

    Устойчив к двум формам данных:

    * плоский словарь ``{'Rule1': '...', 'RulesList': '1'}``;
    * вложенный ``{'Software/Policies/x09/Firewall': {'Rule1': '...'}}``.

    Маркерное значение ``RulesList`` игнорируется. Порядок восстанавливается
    по числовому суффиксу имени значения.

    :param config: словарь из реестра.
    :returns: список строк правил в порядке номеров.
    """
    if not config:
        return []

    flat = {}

    def _absorb(mapping):
        for key, value in mapping.items():
            name = key.rsplit('/', 1)[-1]
            flat[name] = value

    # Если значения сами являются словарями — это вложенная форма.
    if all(isinstance(v, dict) for v in config.values()):
        for section in config.values():
            _absorb(section)
    else:
        _absorb(config)

    rules = []
    for name, value in flat.items():
        if name == MARKER_VALUE:
            continue
        match = re.fullmatch(re.escape(RULE_PREFIX) + r'(\d+)', name)
        if not match:
            continue
        if value is None:
            continue
        rules.append((int(match.group(1)), str(value)))

    rules.sort(key=lambda item: item[0])
    return [value for _, value in rules]


# --------------------------------------------------------------------------- #
# Плагин
# --------------------------------------------------------------------------- #

class X09FirewallApplier(FrontendPlugin):
    """Применяет правила брандмауэра из групповых политик к iptables."""

    # Домен для переводов
    domain = 'x09_firewall'

    def __init__(self, dict_dconf_db, username=None, fs_file_cache=None,
                 registry_path=None):
        super().__init__(dict_dconf_db, username, fs_file_cache, registry_path)

        self._init_plugin_log(
            message_dict={
                'i': {
                    1: "X09 Firewall applier initialized",
                    2: "Applying firewall rules from registry",
                    3: "Firewall rules applied successfully: {applied} rule(s)",
                    4: "Firewall rules saved to {path}",
                },
                'w': {
                    11: "No firewall policy found in registry",
                    12: "Skipping invalid rule '{rule}': {reason}",
                    13: "iptables command not available on this system",
                },
                'e': {
                    20: "Failed to apply firewall rules: {error}",
                    21: "Failed to save firewall rules: {error}",
                    22: "iptables command failed: {command} (exit {code})",
                },
            },
            domain="x09_firewall",
        )

    # ------------------------------------------------------------------ #
    # Основной поток
    # ------------------------------------------------------------------ #

    def run(self, **kwargs):
        """
        Прочитать правила из реестра и применить их к iptables.

        :returns: ``True`` при успехе (в т.ч. при отсутствии политики),
                  ``False`` при ошибке применения.
        """
        try:
            self.log("I1")

            # Плагин предоставляет только create_machine_applier, поэтому
            # менеджер запускает его исключительно в машинном контексте
            # (с правами root). Отдельная проверка username не нужна и была
            # бы ошибочной: в машинном контексте username не пустой.

            if shutil.which(IPTABLES_BIN) is None:
                self.log("W13")
                return True

            config = self.get_dict_registry(
                self._registry_path or REGISTRY_PATH)

            rule_lines = extract_rule_lines(config)
            if not rule_lines:
                self.log("W11")
                # Политика не задана — приводим наши цепочки к пустому виду,
                # чтобы снятые ранее правила не оставались активными.
                self._ensure_chains()
                self._flush_chains()
                self._persist()
                return True

            self.log("I2")

            rules = []
            for line in rule_lines:
                try:
                    rules.append(parse_rule(line))
                except RuleError as exc:
                    self.log("W12", {"rule": line, "reason": str(exc)})

            self._apply_rules(rules)
            self.log("I3", {"applied": len(rules)})

            self._persist()
            return True

        except Exception as exc:  # noqa: BLE001 - плагин не должен «падать»
            self.log("E20", {"error": str(exc)})
            return False

    # ------------------------------------------------------------------ #
    # Работа с iptables
    # ------------------------------------------------------------------ #

    def _apply_rules(self, rules):
        """Пересоздать наши цепочки и наполнить их правилами."""
        self._ensure_chains()
        self._flush_chains()
        for rule in rules:
            self._run_iptables(build_iptables_args(rule))

    def _ensure_chains(self):
        """
        Гарантировать существование пользовательских цепочек и переход в них
        из системных цепочек. Идемпотентно.
        """
        for direction, chain in CHAINS.items():
            parent = PARENT_CHAINS[direction]

            # Создать цепочку, если её ещё нет (-N падает, если существует).
            if not self._chain_exists(chain):
                self._run_iptables(['-N', chain])

            # Подключить к системной цепочке, если ещё не подключена.
            check = self._run_iptables(
                ['-C', parent, '-j', chain], check=False)
            if check.returncode != 0:
                self._run_iptables(['-I', parent, '1', '-j', chain])

    def _flush_chains(self):
        """Очистить только наши цепочки, не трогая прочие правила."""
        for chain in CHAINS.values():
            self._run_iptables(['-F', chain])

    def _chain_exists(self, chain):
        """Проверить существование пользовательской цепочки."""
        result = self._run_iptables(
            ['-L', chain, '-n'], check=False)
        return result.returncode == 0

    def _run_iptables(self, args, check=True):
        """
        Выполнить команду iptables.

        :param args: аргументы после исполняемого файла.
        :param check: если ``True`` — при ненулевом коде возврата пишем ошибку
                      и бросаем исключение; если ``False`` — просто возвращаем
                      результат (для проверок наличия цепочек/правил).
        :returns: объект :class:`subprocess.CompletedProcess`.
        """
        command = [IPTABLES_BIN] + args
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if check and result.returncode != 0:
            self.log("E22", {
                "command": ' '.join(command),
                "code": result.returncode,
            })
            raise RuntimeError(
                "iptables failed: {0} (exit {1}): {2}".format(
                    ' '.join(command), result.returncode,
                    result.stderr.strip()))
        return result

    # ------------------------------------------------------------------ #
    # Персистентность
    # ------------------------------------------------------------------ #

    def _persist(self):
        """
        Сохранить текущий ruleset в файл, чтобы он пережил перезагрузку.
        Использует штатный для ALT механизм ``iptables-save`` → файл.
        """
        if shutil.which(IPTABLES_SAVE_BIN) is None:
            return
        try:
            result = subprocess.run(
                [IPTABLES_SAVE_BIN],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            if result.returncode != 0:
                self.log("E21", {"error": result.stderr.strip()})
                return
            with open(IPTABLES_SAVE_PATH, 'w') as handle:
                handle.write(result.stdout)
            self.log("I4", {"path": IPTABLES_SAVE_PATH})
        except OSError as exc:
            self.log("E21", {"error": str(exc)})


# --------------------------------------------------------------------------- #
# Фабричные функции
# --------------------------------------------------------------------------- #

def create_machine_applier(dict_dconf_db, username=None, fs_file_cache=None,
                           registry_path=None):
    """
    Создать экземпляр плагина для машинного контекста.

    Пользовательская фабрика (``create_user_applier``) намеренно не
    определена: файервол управляется только в машинном контексте. Менеджер
    плагинов при отсутствии ``create_user_applier`` не станет запускать
    плагин в пользовательском контексте.
    """
    return X09FirewallApplier(dict_dconf_db, username, fs_file_cache,
                              registry_path)
