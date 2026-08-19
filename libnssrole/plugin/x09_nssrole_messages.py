# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# x09_nssrole plugin messages

messages = {
    'I0': 'Starting libnss-role applier',
    'I1': 'No libnss-role policy found in registry',
    'I2': 'Using custom role filename: %(filename)s',
    'I3': 'Read %(count)d role definitions from policy',
    'I4': 'No roles to write, skipping',
    'I5': 'Created role directory: %(dir)s',
    'I6': 'Successfully wrote %(count)d roles to %(file)s',
    'I7': 'libnss-role applier completed successfully',

    'W1': 'Invalid filename "%(filename)s", using default: %(default)s',
    'W2': 'Invalid role line (missing or multiple colons): %(line)s',
    'W3': 'Invalid role line format: %(line)s',
    'W4': 'Invalid role line (empty role name): %(line)s',
    'W5': 'Invalid role line (empty group list): %(line)s',
    'W6': 'Skipping invalid role line: %(line)s',
    'W7': 'No valid role definitions found after validation',

    'E1': 'Failed to create role directory %(dir)s: %(error)s',
    'E2': 'Failed to write role file %(file)s: %(error)s',
    'E3': 'libnss-role applier failed: %(error)s',
}

messages_ru = {
    'I0': 'Запуск обработчика libnss-role',
    'I1': 'Политика libnss-role не найдена в реестре',
    'I2': 'Используется пользовательское имя файла ролей: %(filename)s',
    'I3': 'Прочитано определений ролей из политики: %(count)d',
    'I4': 'Нет ролей для записи, пропускаем',
    'I5': 'Создан каталог ролей: %(dir)s',
    'I6': 'Успешно записано ролей: %(count)d в файл %(file)s',
    'I7': 'Обработчик libnss-role завершён успешно',

    'W1': 'Некорректное имя файла "%(filename)s", используется по умолчанию: %(default)s',
    'W2': 'Некорректная строка роли (отсутствует двоеточие или их несколько): %(line)s',
    'W3': 'Некорректный формат строки роли: %(line)s',
    'W4': 'Некорректная строка роли (пустое имя роли): %(line)s',
    'W5': 'Некорректная строка роли (пустой список групп): %(line)s',
    'W6': 'Пропускается некорректная строка роли: %(line)s',
    'W7': 'Не найдено корректных определений ролей после проверки',

    'E1': 'Не удалось создать каталог ролей %(dir)s: %(error)s',
    'E2': 'Не удалось записать файл ролей %(file)s: %(error)s',
    'E3': 'Обработчик libnss-role завершился с ошибкой: %(error)s',
}
