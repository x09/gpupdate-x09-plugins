# x09 Ansible Plugin for GPOA

## Описание

Плагин для применения групповых политик, позволяющий выполнять Ansible playbook на клиентских машинах Linux через механизм групповых политик MSAD/SAMBA AD.

## Возможности

- Выполнение Ansible playbook, заданных через групповую политику
- Поддержка playbook размером до 4096 символов
- Работа в машинном (компьютерном) контексте с правами root
- Автоматическое создание временных файлов для playbook
- Логирование выполнения с поддержкой локализации

## Требования

- Python 3.x
- gpoa (GPO Applier for Linux)
- ansible-core или ansible (команда `ansible-playbook` должна быть доступна)

## Установка

1. Скопируйте файл плагина в директорию плагинов GPOA:
```bash
cp ansible/plugin/x09_ansible.py /usr/lib/gpoa/plugins/
```

2. Установите ADMX шаблоны в хранилище групповых политик:
```bash
cp admx/x09-Ansible.admx /usr/share/PolicyDefinitions/
cp admx/ru-RU/x09-Ansible.adml /usr/share/PolicyDefinitions/ru-RU/
cp admx/en-US/x09-Ansible.adml /usr/share/PolicyDefinitions/en-US/
```

3. Убедитесь, что ansible установлен:
```bash
which ansible-playbook
```

## Использование

### Настройка групповой политики

1. Откройте редактор групповых политик (GPMC)
2. Создайте или отредактируйте GPO
3. Перейдите в раздел:
   - **Computer Configuration** → **Policies** → **Administrative Templates**
   - **Конфигурация компьютера** → **Политики** → **Административные шаблоны**
4. Найдите: **Сторонние шаблоны** → **Управление конфигурацией (Ansible)**
5. Откройте политику: **Управление Ansible Playbook**
6. Включите политику и вставьте содержимое вашего playbook в многострочное поле

### Пример playbook

```yaml
---
- name: Configure system
  hosts: localhost
  tasks:
    - name: Install packages
      package:
        name: 
          - htop
          - vim
        state: present
    
    - name: Create directory
      file:
        path: /opt/myapp
        state: directory
        mode: '0755'
    
    - name: Copy configuration file
      copy:
        content: |
          # Application configuration
          APP_MODE=production
        dest: /etc/myapp.conf
        mode: '0644'
```

### Применение политики

На клиентской машине выполните:
```bash
gpupdate /force
```

Плагин автоматически:
1. Прочитает содержимое playbook из реестра dconf
2. Создаст временный файл с playbook
3. Выполнит `ansible-playbook` с параметрами для localhost
4. Удалит временный файл после выполнения

## Технические детали

### Путь в реестре

Playbook сохраняется в dconf по пути:
```
Software/Policies/x09/Ansible/PlaybookContent
```

### Параметры выполнения

Плагин выполняет ansible-playbook с следующими параметрами:
```bash
ansible-playbook <temp_file.yml> --connection=local --inventory localhost,
```

- `--connection=local` - выполнение на локальной машине без SSH
- `--inventory localhost,` - целевой хост - localhost

### Ограничения

- Максимальный размер playbook: 4096 символов
- Плагин работает только в машинном контексте (требуются права root)
- Playbook должен быть валидным YAML
- Все задачи выполняются на localhost

### Логирование

Логи плагина можно найти в системном журнале GPOA. Коды сообщений:

**Информационные (I):**
- I0: Запуск плагина
- I1: Политика не найдена в реестре
- I2: Прочитано содержимое playbook
- I3: Создан временный файл
- I4: Выполняется ansible-playbook
- I5: Playbook выполнен успешно
- I6: Временный файл удален
- I7: Плагин завершил работу успешно

**Предупреждения (W):**
- W1: Команда ansible-playbook недоступна
- W2: Содержимое playbook пустое
- W3: Размер playbook превышает максимум

**Ошибки (E):**
- E1: Ошибка создания временного файла
- E2: Ошибка записи содержимого
- E3: Ошибка выполнения ansible-playbook
- E4: Ошибка удаления временного файла
- E5: Общая ошибка плагина

## Безопасность

⚠️ **Важно:** Плагин выполняет playbook с правами root. Убедитесь, что:
- Доступ к изменению групповых политик имеют только доверенные администраторы
- Playbook проверены и не содержат потенциально опасных команд
- Политика применяется только к доверенным компьютерам

## Примеры использования

### Установка пакетов

```yaml
---
- name: Install required packages
  hosts: localhost
  tasks:
    - name: Install packages
      package:
        name:
          - mc
          - htop
          - curl
        state: present
```

### Настройка сервиса

```yaml
---
- name: Configure service
  hosts: localhost
  tasks:
    - name: Enable and start chronyd
      systemd:
        name: chronyd
        enabled: yes
        state: started
```

### Создание пользователей

```yaml
---
- name: Create users
  hosts: localhost
  tasks:
    - name: Create app user
      user:
        name: appuser
        state: present
        shell: /bin/bash
        groups: users
        create_home: yes
```

## Разработка

### Структура файлов

```
ansible/
├── plugin/
│   ├── __init__.py
│   └── x09_ansible.py
└── README.md
```

### Тестирование

Для тестирования плагина напрямую (без GPO):

```python
from gpoa_lib import StorageAdapter
from x09_ansible import X09AnsibleApplier

# Создать тестовые данные
test_data = {
    'Software/Policies/x09/Ansible': {
        'PlaybookContent': '''---
- name: Test playbook
  hosts: localhost
  tasks:
    - name: Print message
      debug:
        msg: "Hello from GPO!"
'''
    }
}

# Создать адаптер
adapter = StorageAdapter.from_dict(test_data)

# Создать и запустить плагин
plugin = X09AnsibleApplier(adapter.get_dict())
plugin.apply()
```

## Лицензия

GPL-2.0-or-later

## Авторы

Copyright (C) 2026 x09

## Поддержка

При возникновении проблем проверьте:
1. Установлен ли ansible: `which ansible-playbook`
2. Логи GPOA в системном журнале
3. Валидность YAML синтаксиса playbook
4. Права доступа для выполнения задач playbook
