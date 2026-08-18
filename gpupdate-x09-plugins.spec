%define _unpackaged_files_terminate_build 1
%define _destdir %_datadir/PolicyDefinitions

Name: gpupdate-x09-plugins
Version: 1.0
Release: alt1

Summary: x09 plugins for gpupdate (firewall and role management)
License: GPL-2.0-or-later
Group: System/Configuration/Other
Url: https://github.com/x09/gpupdate-x09-plugins
BuildArch: noarch

BuildRequires(pre): rpm-build-python3
BuildRequires: gettext-tools
BuildRequires: python3-module-pytest

Source0: %name-v%version.tgz

%description
Source package for x09 gpupdate plugins: firewall (iptables) management
and role management (libnss-role). Includes ADMX templates and client-side
plugins that can be installed independently.

# ============================================================================
# ADMX templates package (installed on domain controller)
# ============================================================================

%package -n gpupdate-x09-admx
Summary: ADMX policy templates for x09 gpupdate plugins
License: GPL-2.0-or-later
Group: System/Configuration/Other

%description -n gpupdate-x09-admx
ADMX/ADML templates for x09 gpupdate plugins. Install this package on the
domain controller to enable policy management via Group Policy Editor.

Provides templates for:
- Firewall (iptables) rule management
- Role management (libnss-role)

# ============================================================================
# Firewall plugin package (installed on clients)
# ============================================================================

%package -n gpupdate-x09-firewall-plugin
Summary: Firewall (iptables) management plugin for gpupdate
License: GPL-2.0-or-later
Group: System/Configuration/Other

Requires: iptables
Requires: gpoa-lib >= 0.16

%description -n gpupdate-x09-firewall-plugin
Client-side plugin for gpupdate that reads firewall rules from GPO settings
and applies them to iptables using dedicated managed chains
(FW_PLUGIN_INPUT / FW_PLUGIN_OUTPUT), without touching other rules.
The ruleset is persisted for reboot survival.

# ============================================================================
# libnss-role plugin package (installed on clients)
# ============================================================================

%package -n gpupdate-x09-libnssrole-plugin
Summary: Role management (libnss-role) plugin for gpupdate
License: GPL-2.0-or-later
Group: System/Configuration/Other

Requires: libnss-role
Requires: gpoa-lib >= 0.16

%description -n gpupdate-x09-libnssrole-plugin
Client-side plugin for gpupdate that manages role files in /etc/role.d/
for libnss-role. Enables centralized management of group membership in groups
through domain group policies.

# ============================================================================
# Build and install
# ============================================================================

%prep
%setup -q -n %name-v%version

%build
# Compile translations for firewall plugin
msgfmt -o iptables/locale/ru_RU/LC_MESSAGES/x09_firewall.mo \
    iptables/locale/ru_RU/LC_MESSAGES/x09_firewall.po
msgfmt -o iptables/locale/en_US/LC_MESSAGES/x09_firewall.mo \
    iptables/locale/en_US/LC_MESSAGES/x09_firewall.po

# Compile translations for libnssrole plugin (already compiled, but verify)
cd libnssrole/po
[ -f ru.mo ] || msgfmt ru.po -o ru.mo
[ -f en.mo ] || msgfmt en.po -o en.mo
cd ../..

%install
# ============ ADMX templates ============
mkdir -p %buildroot%_destdir/{ru-RU,en-US}
install -m0644 admx/*.admx %buildroot%_destdir/
install -m0644 admx/ru-RU/*.adml %buildroot%_destdir/ru-RU/
install -m0644 admx/en-US/*.adml %buildroot%_destdir/en-US/

# ============ Firewall plugin ============
mkdir -p %buildroot/usr/lib/gpoa/plugins
install -m0644 iptables/plugin/x09_firewall.py \
    %buildroot/usr/lib/gpoa/plugins/x09_firewall.py

mkdir -p %buildroot/usr/lib/gpoa/plugins/locale/ru_RU/LC_MESSAGES
install -m0644 iptables/locale/ru_RU/LC_MESSAGES/x09_firewall.mo \
    %buildroot/usr/lib/gpoa/plugins/locale/ru_RU/LC_MESSAGES/

mkdir -p %buildroot/usr/lib/gpoa/plugins/locale/en_US/LC_MESSAGES
install -m0644 iptables/locale/en_US/LC_MESSAGES/x09_firewall.mo \
    %buildroot/usr/lib/gpoa/plugins/locale/en_US/LC_MESSAGES/

# ============ libnss-role plugin ============
install -m0644 libnssrole/plugin/x09_nssrole.py \
    %buildroot/usr/lib/gpoa/plugins/x09_nssrole.py

mkdir -p %buildroot/usr/lib/gpoa/plugins/locale/ru_RU/LC_MESSAGES
install -m0644 libnssrole/locale/ru-RU/LC_MESSAGES/x09_nssrole.mo \
    %buildroot/usr/lib/gpoa/plugins/locale/ru_RU/LC_MESSAGES/

mkdir -p %buildroot/usr/lib/gpoa/plugins/locale/en_US/LC_MESSAGES
install -m0644 libnssrole/locale/en-US/LC_MESSAGES/x09_nssrole.mo \
    %buildroot/usr/lib/gpoa/plugins/locale/en_US/LC_MESSAGES/

%check
# Test firewall plugin
cd iptables
%__python3 -m pytest -vra tests/
cd ..

# Test libnssrole plugin
cd libnssrole
%__python3 -m pytest -vra tests/
cd ..

# ============================================================================
# Files
# ============================================================================

%files -n gpupdate-x09-admx
%doc README.md README_en.md
%dir %_destdir
%_destdir/x09-Base.admx
%_destdir/x09-Firewall.admx
%_destdir/x09-LibnssRole.admx
%_destdir/ru-RU/x09-Base.adml
%_destdir/ru-RU/x09-Firewall.adml
%_destdir/ru-RU/x09-LibnssRole.adml
%_destdir/en-US/x09-Base.adml
%_destdir/en-US/x09-Firewall.adml
%_destdir/en-US/x09-LibnssRole.adml

%files -n gpupdate-x09-firewall-plugin
/usr/lib/gpoa/plugins/x09_firewall.py
/usr/lib/gpoa/plugins/locale/ru_RU/LC_MESSAGES/x09_firewall.mo
/usr/lib/gpoa/plugins/locale/en_US/LC_MESSAGES/x09_firewall.mo

%files -n gpupdate-x09-libnssrole-plugin
/usr/lib/gpoa/plugins/x09_nssrole.py
/usr/lib/gpoa/plugins/locale/ru_RU/LC_MESSAGES/x09_nssrole.mo
/usr/lib/gpoa/plugins/locale/en_US/LC_MESSAGES/x09_nssrole.mo

%changelog
* Mon Aug 18 2026 Anton Shevtsov <shevtsov.anton@gmail.com> 1.0-alt1
- Initial release
- Firewall (iptables) management plugin
- Role management (libnss-role) plugin
- Unified ADMX package for both plugins
