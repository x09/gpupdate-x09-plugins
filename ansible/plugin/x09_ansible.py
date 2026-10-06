#!/usr/bin/env python3
#
# GPOA - GPO Applier for Linux
# x09 Ansible plugin
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
Плагин gpupdate для выполнения Ansible playbooks через групповые политики.

Playbook указывается в ADMX-политике «Управление конфигурацией (Ansible)»
по пути ``Software/Policies/x09/Ansible`` как значение ``PlaybookFilename``.

Плагин:
1. Читает имя файла из политики (например, configure_system.yml)
2. Определяет GUID привязанных GPO через get_current_gpo_guids()
3. Скачивает playbook из SYSVOL по пути:
   \\\\domain\\sysvol\\domain\\Policies\\{GUID}\\Machine\\Scripts\\YML\\{filename}
4. Использует smbc (libsmbclient) с Kerberos аутентификацией машины
5. Кэширует файлы в /var/cache/gpupdate_file_cache/ansible_playbooks/
6. Проверяет актуальность кэша при каждом gpupdate
7. Выполняет ansible-playbook локально
"""

import os
import subprocess
from pathlib import Path

import smbc

from gpoa_lib.plugin.plugin_base import FrontendPlugin
from gpoa_lib.storage.gpp_state import get_current_gpo_guids
from gpoa_lib.util.paths import file_cache_dir
from gpoa_lib.util.util import runcmd


# --------------------------------------------------------------------------- #
# Константы
# --------------------------------------------------------------------------- #

#: Ветка реестра, куда ADMX-политика записывает имя файла playbook.
REGISTRY_PATH = 'Software/Policies/x09/Ansible'

#: Имя значения в реестре с именем файла playbook
PLAYBOOK_FILENAME_KEY = 'PlaybookFilename'

#: Подкаталог в file_cache_dir для хранения playbooks
CACHE_SUBDIR = 'ansible_playbooks'


# --------------------------------------------------------------------------- #
# Основной класс плагина
# --------------------------------------------------------------------------- #

class X09AnsibleApplier(FrontendPlugin):
    """
    Плагин для выполнения Ansible playbooks через групповые политики.
    """

    # Домен для переводов
    domain = 'x09_ansible'

    def __init__(self, dict_dconf_db, username=None, fs_file_cache=None, registry_path=None):
        """
        Инициализация плагина Ansible.

        Args:
            dict_dconf_db (dict): Словарь с данными из реестра
            username (str): Имя пользователя (не используется в машинном контексте)
            fs_file_cache: Кэш файловой системы
            registry_path (str): Переопределение пути в реестре
        """
        super().__init__(dict_dconf_db, username, fs_file_cache, registry_path)

        # Инициализация системы логирования
        self._init_plugin_log(
            message_dict={
                'i': {
                    1: "Starting Ansible applier",
                    2: "Read playbook filename from policy: {filename}",
                    3: "Downloaded playbook from SYSVOL: {file}",
                    4: "Using cached playbook: {file}",
                    5: "Executing ansible-playbook: {playbook}",
                    6: "Ansible playbook executed successfully",
                    7: "Cleaned up stale cache file: {file}",
                },
                'w': {
                    1: "No playbook filename specified in policy",
                    2: "Playbook file not found in any GPO",
                    3: "Cannot determine domain name",
                    4: "Using cached playbook (download failed): {file}",
                },
                'e': {
                    1: "Failed to determine domain: {error}",
                    2: "Failed to download playbook {file}: {error}",
                    3: "Failed to get current GPO GUIDs: {error}",
                    4: "ansible-playbook execution failed: {error}",
                    5: "Playbook file not found and no cache available: {filename}",
                }
            },
            domain="x09_ansible"
        )

        # Путь к кэшу playbooks
        self.cache_dir = Path(file_cache_dir()) / CACHE_SUBDIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Инициализация SMB context с Kerberos (как в fs_file_cache)
        self.smb_ctx = smbc.Context(use_kerberos=1)

    def run(self, **kwargs):
        """
        Основной метод выполнения плагина.

        Returns:
            bool: True если успешно, False при ошибке
        """
        try:
            self.log("I1")

            # Получение имени файла playbook из политики
            config = self.get_dict_registry(self._registry_path or REGISTRY_PATH)

            if not config or PLAYBOOK_FILENAME_KEY not in config:
                self.log("W1")
                return True

            filename = config[PLAYBOOK_FILENAME_KEY]
            if not filename or not filename.strip():
                self.log("W1")
                return True

            filename = filename.strip()
            self.log("I2", {"filename": filename})

            # Получить playbook (скачать или из кэша)
            playbook_path = self._get_playbook(filename)

            if not playbook_path:
                self.log("E5", {"filename": filename})
                return False

            # Выполнить ansible-playbook
            self.log("I5", {"playbook": playbook_path})
            success = self._execute_playbook(playbook_path)

            if success:
                self.log("I6")
            else:
                self.log("E4", {"error": "See ansible output above"})

            # Очистка устаревших файлов из кэша
            self._cleanup_stale_cache()

            return success

        except Exception as e:
            self.log("E4", {"error": str(e)})
            return False

    def _get_playbook(self, filename):
        """
        Получить путь к playbook: скачать из SYSVOL или использовать кэш.

        Args:
            filename (str): Имя файла playbook

        Returns:
            Path: Путь к локальному файлу playbook или None
        """
        # Получить список GUID привязанных GPO
        try:
            gpo_guids = get_current_gpo_guids()
        except Exception as e:
            self.log("E3", {"error": str(e)})
            return None

        if not gpo_guids:
            self.log("W2")
            return None

        # Попробовать скачать из каждого GPO (собираем ошибки, но не логируем сразу)
        download_errors = []
        for gpo_guid in gpo_guids:
            playbook_path, error = self._download_playbook(gpo_guid, filename)
            if playbook_path:
                return playbook_path
            if error:
                download_errors.append((gpo_guid, error))

        # Если не удалось скачать, проверить кэш
        for gpo_guid in gpo_guids:
            cache_file = self.cache_dir / f"{gpo_guid}_{filename}"
            if cache_file.exists():
                self.log("W4", {"file": str(cache_file)})
                return cache_file

        # Если вообще ничего не найдено, залогировать ошибки скачивания
        if download_errors:
            self.log("W2")
            # Логируем только последнюю ошибку, чтобы не засорять лог
            last_gpo, last_error = download_errors[-1]
            self.log("E2", {"file": filename, "error": last_error})

        return None

    def _get_domain(self):
        """
        Определить домен машины из конфигурации Kerberos/realm.

        Returns:
            str: Доменное имя или None
        """
        # Попытка 1: realm list
        returncode, output = runcmd(['realm', 'list'])
        if returncode == 0 and output:
            for line in output.split('\n'):
                if 'realm-name:' in line.lower():
                    domain = line.split(':', 1)[1].strip()
                    return domain

        # Попытка 2: /etc/krb5.conf
        try:
            with open('/etc/krb5.conf', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('default_realm'):
                        # default_realm = TEST.ALT
                        domain = line.split('=', 1)[1].strip()
                        return domain.lower()
        except Exception:
            pass

        # Попытка 3: hostname -d
        returncode, output = runcmd(['hostname', '-d'])
        if returncode == 0 and output.strip():
            return output.strip()

        self.log("W3")
        return None

    def _download_playbook(self, gpo_guid, filename):
        """
        Скачать playbook из SYSVOL через smbc (libsmbclient) с Kerberos.

        Args:
            gpo_guid (str): GUID политики (например, {A731D8D6-...})
            filename (str): Имя файла playbook

        Returns:
            tuple: (Path к скачанному файлу или None, текст ошибки или None)
        """
        domain = self._get_domain()
        if not domain:
            return None, "Domain not found"

        # SMB URL к файлу в SYSVOL
        # smb://domain/sysvol/domain/Policies/{GUID}/Machine/Scripts/YML/file.yml
        smb_url = f"smb://{domain}/sysvol/{domain}/Policies/{gpo_guid}/Machine/Scripts/YML/{filename}"

        # Локальный путь в кэше
        cache_file = self.cache_dir / f"{gpo_guid}_{filename}"

        # Проверить актуальность кэша
        if cache_file.exists():
            if self._is_cache_valid(smb_url, cache_file):
                self.log("I4", {"file": str(cache_file)})
                return cache_file, None

        # Скачать файл через smbc
        try:
            # Открыть удалённый файл (Kerberos используется автоматически)
            remote_file = self.smb_ctx.open(smb_url, os.O_RDONLY)
            content = remote_file.read()
            remote_file.close()

            # Записать в локальный кэш
            with open(cache_file, 'wb') as f:
                f.write(content)

            self.log("I3", {"file": filename})
            return cache_file, None

        except Exception as e:
            return None, str(e)

    def _is_cache_valid(self, smb_url, cache_file):
        """
        Проверить актуальность кэшированного файла по размеру.

        Args:
            smb_url (str): SMB URL к файлу на SYSVOL
            cache_file (Path): Локальный кэшированный файл

        Returns:
            bool: True если кэш актуален
        """
        try:
            # Получить stat удалённого файла через smbc
            stat_info = self.smb_ctx.stat(smb_url)

            # stat_info это tuple в формате os.stat: (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime)
            remote_size = stat_info[6]  # st_size

            # Сравнить размер с локальным файлом
            local_size = cache_file.stat().st_size
            return local_size == remote_size

        except Exception:
            # При любой ошибке (файл не найден, нет доступа) считаем кэш невалидным
            return False

    def _execute_playbook(self, playbook_path):
        """
        Выполнить ansible-playbook локально.

        Args:
            playbook_path (Path): Путь к файлу playbook

        Returns:
            bool: True если выполнение успешно
        """
        cmd = [
            'ansible-playbook',
            str(playbook_path),
            '--connection=local',
            '-i', 'localhost,'
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=False,  # Выводить в консоль напрямую
                text=True
            )
            return result.returncode == 0
        except Exception as e:
            self.log("E4", {"error": str(e)})
            return False

    def _cleanup_stale_cache(self):
        """
        Удалить из кэша файлы от отвязанных GPO.
        """
        try:
            current_guids = set(get_current_gpo_guids())

            # Проверить все файлы в кэше
            for cache_file in self.cache_dir.glob('*'):
                if not cache_file.is_file():
                    continue

                # Формат имени: {GUID}_{filename}
                filename = cache_file.name
                if '_' not in filename:
                    continue

                gpo_guid = filename.split('_', 1)[0]

                # Если GUID больше не в списке текущих - удалить
                if gpo_guid not in current_guids:
                    cache_file.unlink()
                    self.log("I7", {"file": str(cache_file)})
        except Exception:
            # Ошибки очистки не критичны
            pass


# --------------------------------------------------------------------------- #
# Фабричные функции (требуются для plugin_manager)
# --------------------------------------------------------------------------- #

def create_machine_applier(dict_dconf_db, username=None, fs_file_cache=None, registry_path=None):
    """
    Фабричная функция для создания экземпляра плагина для машинного контекста.

    Args:
        dict_dconf_db (dict): Словарь с данными из реестра
        username (str): Имя пользователя
        fs_file_cache: Кэш файловой системы
        registry_path (str): Переопределение пути в реестре

    Returns:
        X09AnsibleApplier: Экземпляр плагина
    """
    return X09AnsibleApplier(dict_dconf_db, username, fs_file_cache, registry_path)


def create_user_applier(dict_dconf_db, username=None, fs_file_cache=None, registry_path=None):
    """
    Фабричная функция для создания экземпляра плагина для пользовательского контекста.

    Примечание: Ansible плагин работает только в машинном контексте.
    Эта функция требуется для совместимости с plugin_manager.

    Args:
        dict_dconf_db (dict): Словарь с данными из реестра
        username (str): Имя пользователя
        fs_file_cache: Кэш файловой системы
        registry_path (str): Переопределение пути в реестре

    Returns:
        None: Плагин не работает в пользовательском контексте
    """
    # Ansible плагин работает только в машинном контексте
    return None
