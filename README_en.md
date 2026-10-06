# x09 Plugins for gpupdate

A set of plugins for the gpupdate (GPOA) group policy system on ALT OS, enabling centralized management of various client machine configuration aspects through domain group policies.

## Components

### Firewall (iptables)

The `x09_firewall` plugin manages firewall rules (iptables) on client machines.

**Features:**
- Centralized iptables rules management via ADMX templates
- Support for TCP/UDP protocols, inbound and outbound directions
- Actions: Allow, Deny, Reject (with notification)
- Filtering by source and destination IP addresses (with CIDR support)
- Support for single ports, ranges (53-153), and lists (22,80,443)

**Rule format:**
```
Action=Allow|Deny|Reject;Direction=In|Out;Protocol=TCP|UDP;Port=port;Source=IP;Destination=IP
```

**Examples:**
```
Action=Allow;Direction=In;Protocol=TCP;Port=80;Source=10.0.0.0/24
Action=Deny;Direction=Out;Protocol=UDP;Port=53;Destination=8.8.8.8
Action=Allow;Direction=In;Protocol=TCP;Port=22,80,443
```

**Limitations:**
- Only classic iptables (IPv4) is supported, INPUT/OUTPUT chains
- IPv6 (ip6tables) and nftables are not supported
- Port is applied as destination port (--dport) for both directions

---

### Role Management (libnss-role)

The `x09_nssrole` plugin manages role files in `/etc/role.d/`, defining group membership in groups via the libnss-role NSS module.

**Features:**
- Centralized management of user roles and privileges
- Definition of group membership in groups (recursive application)
- Support for domain groups (including Cyrillic names)
- Configurable role file name (default: custom-roles.role)

**Role definition format:**
```
<group>:<group>[,<group>]*
```

where the left side of the colon is the role name (group that will be included in other groups), and the right side is a comma-separated list of groups that this role belongs to.

**Examples:**
```
users: cdwriter, cdrom, audio, video, camera, floppy
localadmins: wheel
domain admins:localadmins
WIN\domain admins:localadmins
powerusers: remote, users
```

**Allowed characters in group names:**
- Latin, Cyrillic, digits
- Symbols: `\` `-` `_` (backslash, hyphen, underscore)
- Spaces

**Application strategy:**
The file `/etc/role.d/<filename>` is completely overwritten with policy content on each gpupdate run.

---


### Ansible Playbook Execution Plugin

**Description**

A group policy application plugin that allows executing Ansible playbooks on Linux client machines through the MSAD/SAMBA AD group policy mechanism.

**Features**

- Execution of Ansible playbooks defined via group policy
- Works in machine (computer) context with root privileges
- YML playbook file must be placed in the policy folder in the \Machine\Scripts\YML subfolder (\\DOMAIN.ZONE\sysvol\domain.zone\Policies\{--GPO-UUID--}\Machine\Scripts\YML)

## Requirements

- Python 3.x
- gpoa (GPO Applier for Linux)
- ansible-core or ansible (`ansible-playbook` command must be available)
- python3-module-smbc

When installing via RPM package, all dependencies are resolved automatically.

## Installation

### ADMX Templates (on domain controller)

All ADMX templates are installed with a single `admx-x09` package:

```bash
# Package installation
apt-get install admx-x09

# Or manually:
cp admx/*.admx /usr/share/PolicyDefinitions/
cp admx/ru-RU/*.adml /usr/share/PolicyDefinitions/ru-RU/
cp admx/en-US/*.adml /usr/share/PolicyDefinitions/en-US/

# Load into SysVol
samba-tool gpo admxload -UAdministrator
```

In the group policy editor, templates will appear in the **"Third-party Templates"** category with subcategories:
- Firewall (iptables)
- Role Management (libnss-role)
- Ansible Playbook Management (ansible)

### Plugins (on client machines)

Plugins are installed as separate packages by choice:

**Firewall plugin:**
```bash
apt-get install gpupdate-x09-firewall-plugin
```

Installs:
- `/usr/lib/gpoa/plugins/x09_firewall.py`
- `/usr/lib/gpoa/plugins/locale/{ru_RU,en_US}/LC_MESSAGES/x09_firewall.mo`

**Role management plugin:**
```bash
apt-get install gpupdate-x09-libnssrole-plugin
```

Installs:
- `/usr/lib/gpoa/plugins/x09_nssrole.py`
- `/usr/lib/gpoa/plugins/locale/{ru_RU,en_US}/LC_MESSAGES/x09_nssrole.mo`

**Ansible playbook execution plugin:**
```bash
apt-get install gpupdate-x09-ansible-plugin
```

Installs:
- `/usr/lib/gpoa/plugins/x09_ansible.py`


### Requirements

**On domain controller:**
- Samba 4 (DC)
- `admx-x09` package

**On client machines:**
- `gpoa-lib` (gpupdate plugin mechanism)
- For firewall plugin: `iptables`, `iptables-services`
- For libnssrole plugin: `libnss-role`
- For ansible plugin: `ansible-core`, `python3-module-smbc`

---

## Applying Policies

After creating and configuring GPO on the domain controller, run on the client:

```bash
gpupdate -t COMPUTER -s -l 0
```

Plugins run in machine context (with root privileges) on every policy update.

## Localization

Some plugins support Russian and English languages via GNU gettext. The displayed language is determined by the system locale.
