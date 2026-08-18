# x09 Plugins for gpupdate

A set of plugins for the gpupdate (GPOA) group policy system on ALT OS, enabling centralized management of various client machine configuration aspects through domain group policies.

## Components

### Firewall (iptables)

The `x09_firewall` plugin manages firewall rules (iptables) on client machines.

**Features:**
- Centralized iptables rules management via ADMX templates
- TCP/UDP protocol support, inbound and outbound directions
- Actions: Allow, Deny, Reject (with notification)
- Source and destination IP address filtering (with CIDR support)
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

The `x09_nssrole` plugin manages role files in `/etc/role.d/`, which define group membership in groups through the libnss-role NSS module.

**Features:**
- Centralized management of user roles and privileges
- Define group membership in groups (recursive application)
- Support for domain groups (including Cyrillic names)
- Configurable role file name (default: custom-roles.role)

**Role definition format:**
```
<group>:<group>[,<group>]*
```

where left of the colon is the role name (group that will be included in other groups), right of the colon is a comma-separated list of groups this role is included in.

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
- symbols: `\` `-` `_` (backslash, hyphen, underscore)
- spaces

**Application strategy:**
The file `/etc/role.d/<filename>` is completely overwritten with the content from the policy each time gpupdate runs.

---

## Installation

### ADMX Templates (on domain controller)

All ADMX templates are installed as a single package `admx-x09`:

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

In the Group Policy Editor, templates will appear in the **"Third-party templates"** category with subcategories:
- Firewall (iptables)
- Role Management (libnss-role)

### Plugins (on client machines)

Plugins are installed as separate packages as needed:

**Firewall plugin:**
```bash
apt-get install gpupdate-firewall-plugin
```

Installs:
- `/usr/lib/gpoa/plugins/x09_firewall.py`
- `/usr/lib/gpoa/plugins/locale/{ru_RU,en_US}/LC_MESSAGES/x09_firewall.mo`

**Role management plugin:**
```bash
apt-get install gpupdate-nssrole-plugin
```

Installs:
- `/usr/lib/gpoa/plugins/x09_nssrole.py`
- `/usr/lib/gpoa/plugins/locale/{ru_RU,en_US}/LC_MESSAGES/x09_nssrole.mo`

### Requirements

**On domain controller:**
- Samba 4 (DC)
- Package `admx-x09`

**On client machines:**
- `gpoa-lib` (gpupdate plugin mechanism)
- For firewall plugin: `iptables`, `iptables-services`
- For nssrole plugin: `libnss-role`

---

## Applying Policies

After creating and configuring GPO on the domain controller, run on the client:

```bash
gpupdate -t COMPUTER -s -l 0
```

Plugins run in machine context (with root privileges) each time policies are updated.

## Localization

All plugins support Russian and English languages via GNU gettext. The displayed language is determined by the system locale.

## Repository Structure

```
gpupdate-x09-plugins-v1.0/
├── admx/                    # ADMX templates (single package for all plugins)
│   ├── x09-Base.admx        # Base categories and definitions
│   ├── x09-Firewall.admx    # Template for firewall
│   ├── x09-LibnssRole.admx  # Template for role management
│   ├── ru-RU/               # Russian translations
│   └── en-US/               # English translations
├── iptables/                # Firewall plugin
│   ├── plugin/x09_firewall.py
│   ├── locale/
│   └── tests/
└── libnssrole/              # Role management plugin
    ├── plugin/x09_nssrole.py
    ├── locale/
    ├── po/
    └── tests/
```

