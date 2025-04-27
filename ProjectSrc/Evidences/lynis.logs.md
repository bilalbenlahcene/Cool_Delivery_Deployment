[ec2-user@ip-172-31-44-223 ~]$ sudo lynis audit system

[ Lynis 3.1.1 ]

################################################################################
  Lynis comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
  welcome to redistribute it under the terms of the GNU General Public License.
  See the LICENSE file for details about using this software.

  2007-2021, CISOfy - https://cisofy.com/lynis/
  Enterprise support available (compliance, plugins, interface and tools)
################################################################################

[+] Initializing program
------------------------

- Detecting OS...                                           [ DONE ]
- Checking profiles...                                      [ DONE ]

---

Program version:           3.1.1
  Operating system:          Linux
  Operating system name:     Amazon Linux
  Operating system version:  2
  Kernel version:            5.10.235
  Hardware platform:         x86_64
  Hostname:                  ip-172-31-44-223
---------------------------------------------

Profiles:                  /etc/lynis/default.prf
  Log file:                  /var/log/lynis.log
  Report file:               /var/log/lynis-report.dat
  Report version:            1.0
  Plugin directory:          /usr/share/lynis/plugins
-----------------------------------------------------

Auditor:                   [Not Specified]
  Language:                  en
  Test category:             all
  Test group:                all
--------------------------------

- Program update status...                                  [ UPDATE AVAILABLE ]

  ===============================================================================
  Lynis update available
  ======================

  Current version is more than 4 months old

  Current version : 311   Latest version : 314

  Please update to the latest version.
  New releases include additional features, bug fixes, tests, and baselines.

  Download the latest version:

  Packages (DEB/RPM) -  https://packages.cisofy.com
  Website (TAR)      -  https://cisofy.com/downloads/
  GitHub (source)    -  https://github.com/CISOfy/lynis

  ===============================================================================

[+] System tools
----------------

- Scanning available tools...
- Checking system binaries...

[+] Plugins (phase 1)
---------------------

 Note: plugins have more extensive tests and may take several minutes to complete

- Plugins enabled                                           [ NONE ]

[+] Boot and services
---------------------

- Service Manager                                           [ systemd ]
- Checking UEFI boot                                        [ DISABLED ]
- Checking presence GRUB2                                   [ FOUND ]
  - Checking for password protection                        [ OK ]
- Check running services (systemctl)                        [ DONE ]
  Result: found 21 running services
- Check enabled services at boot (systemctl)                [ DONE ]
  Result: found 40 enabled services
- Check startup files (permissions)                         [ OK ]

[+] Kernel
----------

- Checking default runlevel                                 [ runlevel 5 ]
- Checking CPU support (NX/PAE)
  CPU support: PAE and/or NoeXecute supported               [ FOUND ]
- Checking kernel version and release                       [ DONE ]
- Checking kernel type                                      [ DONE ]
- Checking loaded kernel modules                            [ DONE ]
  Found 52 active modules
- Checking Linux kernel configuration file                  [ FOUND ]
- Checking default I/O kernel scheduler                     [ NOT FOUND ]
- Checking core dumps configuration
  - configuration in systemd conf files                     [ DEFAULT ]
  - configuration in /etc/profile                           [ DEFAULT ]
  - 'hard' configuration in /etc/security/limits.conf       [ DEFAULT ]
  - 'soft' configuration in /etc/security/limits.conf       [ DEFAULT ]
  - Checking setuid core dumps configuration                [ DISABLED ]
- Check if reboot is needed                                 [ NO ]

[+] Memory and Processes
------------------------

- Checking /proc/meminfo                                    [ FOUND ]
- Searching for dead/zombie processes                       [ NOT FOUND ]
- Searching for IO waiting processes                        [ NOT FOUND ]
- Search prelink tooling                                    [ NOT FOUND ]

[+] Users, Groups and Authentication
------------------------------------

- Administrator accounts                                    [ OK ]
- Unique UIDs                                               [ OK ]
- Consistency of group files (grpck)                        [ OK ]
- Unique group IDs                                          [ OK ]
- Unique group names                                        [ OK ]
- Password file consistency                                 [ OK ]
- Password hashing methods                                  [ OK ]
- Checking password hashing rounds                          [ DISABLED ]
- Query system users (non daemons)                          [ DONE ]
- NIS+ authentication support                               [ NOT ENABLED ]
- NIS authentication support                                [ NOT ENABLED ]
- Sudoers file(s)                                           [ FOUND ]
  - Permissions for directory: /etc/sudoers.d               [ OK ]
  - Permissions for: /etc/sudoers                           [ OK ]
  - Permissions for: /etc/sudoers.d/90-cloud-init-users     [ OK ]
- PAM password strength tools                               [ OK ]
- PAM configuration file (pam.conf)                         [ NOT FOUND ]
- PAM configuration files (pam.d)                           [ FOUND ]
- PAM modules                                               [ FOUND ]
- LDAP module in PAM                                        [ NOT FOUND ]
- Accounts without expire date                              [ OK ]
- Accounts without password                                 [ OK ]
- Locked accounts                                           [ FOUND ]
- Checking user password aging (minimum)                    [ DISABLED ]
- User password aging (maximum)                             [ DISABLED ]
- Checking expired passwords                                [ OK ]
- Checking Linux single user mode authentication            [ OK ]
- Determining default umask
  - umask (/etc/profile and /etc/profile.d)                 [ SUGGESTION ]
  - umask (/etc/login.defs)                                 [ OK ]
  - umask (/etc/init.d/functions)                           [ SUGGESTION ]
- LDAP authentication support                               [ NOT ENABLED ]
- Logging failed login attempts                             [ DISABLED ]

[+] Shells
----------

- Checking shells from /etc/shells
  Result: found 6 shells (valid shells: 6).
  - Session timeout settings/tools                          [ NONE ]
- Checking default umask values
  - Checking default umask in /etc/bashrc                   [ WEAK ]
  - Checking default umask in /etc/csh.cshrc                [ WEAK ]
  - Checking default umask in /etc/profile                  [ WEAK ]

[+] File systems
----------------

- Checking mount points
  - Checking /home mount point                              [ SUGGESTION ]
  - Checking /tmp mount point                               [ SUGGESTION ]
  - Checking /var mount point                               [ SUGGESTION ]
- Query swap partitions (fstab)                             [ NONE ]
- Testing swap partitions                                   [ OK ]
- Testing /proc mount (hidepid)                             [ SUGGESTION ]
- Checking for old files in /tmp                            [ OK ]
- Checking /tmp sticky bit                                  [ OK ]
- Checking /var/tmp sticky bit                              [ OK ]
- ACL support root file system                              [ ENABLED ]
- Mount options of /                                        [ NON DEFAULT ]
- Mount options of /dev                                     [ PARTIALLY HARDENED ]
- Mount options of /dev/shm                                 [ PARTIALLY HARDENED ]
- Mount options of /run                                     [ HARDENED ]
- Total without nodev:8 noexec:11 nosuid:6 ro or noexec (W^X): 11 of total 28
- Checking Locate database                                  [ FOUND ]
- Disable kernel support of some filesystems

[+] USB Devices
---------------

- Checking usb-storage driver (modprobe config)             [ NOT DISABLED ]
- Checking USBGuard                                         [ NOT FOUND ]

[+] Storage
-----------

- Checking firewire ohci driver (modprobe config)           [ NOT DISABLED ]

[+] NFS
-------

- Query rpc registered programs                             [ DONE ]
- Query NFS versions                                        [ DONE ]
- Query NFS protocols                                       [ DONE ]
- Check running NFS daemon                                  [ NOT FOUND ]

[+] Name services
-----------------

- Checking search domains                                   [ FOUND ]
- Checking /etc/resolv.conf options                         [ FOUND ]
- Searching DNS domain name                                 [ FOUND ]
  Domain name: eu-west-1.compute.internal
- Checking /etc/hosts
  - Duplicate entries in hosts file                         [ NONE ]
  - Presence of configured hostname in /etc/hosts           [ NOT FOUND ]
  - Hostname mapped to localhost                            [ NOT FOUND ]
  - Localhost mapping to IP address                         [ OK ]

[+] Ports and packages
----------------------

- Searching package managers
  - Searching RPM package manager                           [ FOUND ]
    - Querying RPM package manager
- YUM package management consistency                        [ OK ]
- Checking package database duplicates                      [ OK ]
- Checking package database for problems                    [ OK ]
- Checking missing security packages                        [ OK ]
- Checking GPG checks (yum.conf)                            [ OK ]
- Checking package audit tool                               [ INSTALLED ]
  Found: yum-security

[+] Networking
--------------

- Checking IPv6 configuration                               [ ENABLED ]
  Configuration method                                    [ AUTO ]
  IPv6 only                                               [ NO ]
- Checking configured nameservers
  - Testing nameservers
    Nameserver: 172.31.0.2                                [ OK ]
  - Minimal of 2 responsive nameservers                     [ WARNING ]
- Checking default gateway                                  [ DONE ]
- Getting listening ports (TCP/UDP)                         [ DONE ]
- Checking promiscuous interfaces                           [ OK ]
- Checking waiting connections                              [ OK ]
- Checking status DHCP client                               [ RUNNING ]
- Checking for ARP monitoring software                      [ NOT FOUND ]
- Uncommon network protocols                                [ 0 ]

[+] Printers and Spools
-----------------------

- Checking cups daemon                                      [ NOT FOUND ]
- Checking lp daemon                                        [ NOT RUNNING ]

[+] Software: e-mail and messaging
----------------------------------

[+] Software: firewalls
-----------------------

- Checking iptables support                                 [ FOUND ]
  - Checking iptables policies of chains                    [ FOUND ]
    - Checking chain INPUT (table:
      filter, policy ACCEPT)  [ ACCEPT ]
  - Checking for empty ruleset                              [ OK ]
  - Checking for unused rules                               [ FOUND ]
- Checking host based firewall                              [ ACTIVE ]

[+] Software: webserver
-----------------------

- Checking Apache                                           [ NOT FOUND ]
- Checking nginx                                            [ NOT FOUND ]

[+] SSH Support
---------------

- Checking running SSH daemon                               [ FOUND ]
  - Searching SSH configuration                             [ FOUND ]
  - OpenSSH option: AllowTcpForwarding                      [ SUGGESTION ]
  - OpenSSH option: ClientAliveCountMax                     [ SUGGESTION ]
  - OpenSSH option: ClientAliveInterval                     [ OK ]
  - OpenSSH option: FingerprintHash                         [ OK ]
  - OpenSSH option: GatewayPorts                            [ OK ]
  - OpenSSH option: IgnoreRhosts                            [ OK ]
  - OpenSSH option: LoginGraceTime                          [ OK ]
  - OpenSSH option: LogLevel                                [ SUGGESTION ]
  - OpenSSH option: MaxAuthTries                            [ SUGGESTION ]
  - OpenSSH option: MaxSessions                             [ SUGGESTION ]
  - OpenSSH option: PermitRootLogin                         [ SUGGESTION ]
  - OpenSSH option: PermitUserEnvironment                   [ OK ]
  - OpenSSH option: PermitTunnel                            [ OK ]
  - OpenSSH option: Port                                    [ SUGGESTION ]
  - OpenSSH option: PrintLastLog                            [ OK ]
  - OpenSSH option: StrictModes                             [ OK ]
  - OpenSSH option: TCPKeepAlive                            [ SUGGESTION ]
  - OpenSSH option: UseDNS                                  [ SUGGESTION ]
  - OpenSSH option: X11Forwarding                           [ SUGGESTION ]
  - OpenSSH option: AllowAgentForwarding                    [ SUGGESTION ]
  - OpenSSH option: UsePrivilegeSeparation                  [ OK ]
  - OpenSSH option: AllowUsers                              [ NOT FOUND ]
  - OpenSSH option: AllowGroups                             [ NOT FOUND ]

[+] SNMP Support
----------------

- Checking running SNMP daemon                              [ NOT FOUND ]

[+] Databases
-------------

    No database engines found

[+] LDAP Services
-----------------

- Checking OpenLDAP instance                                [ NOT FOUND ]

[+] PHP
-------

- Checking PHP                                              [ NOT FOUND ]

[+] Squid Support
-----------------

- Checking running Squid daemon                             [ NOT FOUND ]

[+] Logging and files
---------------------

- Checking for a running log daemon                         [ OK ]
  - Checking Syslog-NG status                               [ NOT FOUND ]
  - Checking systemd journal status                         [ FOUND ]
  - Checking Metalog status                                 [ NOT FOUND ]
  - Checking RSyslog status                                 [ FOUND ]
  - Checking RFC 3195 daemon status                         [ NOT FOUND ]
  - Checking minilogd instances                             [ NOT FOUND ]
- Checking logrotate presence                               [ OK ]
- Checking remote logging                                   [ NOT ENABLED ]
- Checking log directories (static list)                    [ DONE ]
- Checking open log files                                   [ DONE ]
- Checking deleted files in use                             [ DONE ]

[+] Insecure services
---------------------

- Installed inetd package                                   [ NOT FOUND ]
- Installed xinetd package                                  [ OK ]
  - xinetd status                                           [ NOT ACTIVE ]
- Installed rsh client package                              [ OK ]
- Installed rsh server package                              [ OK ]
- Installed telnet client package                           [ OK ]
- Installed telnet server package                           [ NOT FOUND ]
- Checking NIS client installation                          [ OK ]
- Checking NIS server installation                          [ OK ]
- Checking TFTP client installation                         [ OK ]
- Checking TFTP server installation                         [ OK ]

[+] Banners and identification
------------------------------

- /etc/issue                                                [ FOUND ]
  - /etc/issue contents                                     [ WEAK ]
- /etc/issue.net                                            [ FOUND ]
  - /etc/issue.net contents                                 [ WEAK ]

[+] Scheduled tasks
-------------------

- Checking crontab and cronjob files                        [ DONE ]
- Checking atd status                                       [ RUNNING ]
  - Checking at users                                       [ DONE ]
  - Checking at jobs                                        [ NONE ]

[+] Accounting
--------------

- Checking accounting information                           [ OK ]
- Checking sysstat accounting data                          [ ENABLED ]
- Checking auditd                                           [ ENABLED ]
  - Checking audit rules                                    [ SUGGESTION ]
  - Checking audit configuration file                       [ OK ]
  - Checking auditd log file                                [ FOUND ]

[+] Time and Synchronization
----------------------------

[+] Cryptography
----------------

- Checking for expired SSL certificates [0/4]               [ NONE ]
- Found 0 encrypted and 0 unencrypted swap devices in use.  [ OK ]
- Kernel entropy is sufficient                              [ YES ]
- HW RNG & rngd                                             [ NO ]
- SW prng                                                   [ NO ]
- MOR variable not found                                    [ WEAK ]

[+] Virtualization
------------------

[+] Containers
--------------

[+] Security frameworks
-----------------------

- Checking presence AppArmor                                [ NOT FOUND ]
- Checking presence SELinux                                 [ FOUND ]
  - Checking SELinux status                                 [ DISABLED ]
- Checking presence TOMOYO Linux                            [ NOT FOUND ]
- Checking presence grsecurity                              [ NOT FOUND ]
- Checking for implemented MAC framework                    [ NONE ]

[+] Software: file integrity
----------------------------

- Checking file integrity tools
- Checking presence integrity tool                          [ NOT FOUND ]

[+] Software: System tooling
----------------------------

- Checking automation tooling
- Automation tooling                                        [ NOT FOUND ]
- Checking presence of Fail2ban                             [ FOUND ]
  - Checking Fail2ban jails                                 [ DISABLED ]
- Checking for IDS/IPS tooling                              [ FOUND ]

[+] Software: Malware
---------------------

- Checking Rootkit Hunter                                   [ FOUND ]
- Checking ClamAV scanner                                   [ FOUND ]
- Malware software components                               [ FOUND ]
  - Active agent                                            [ NOT FOUND ]
  - Rootkit scanner                                         [ FOUND ]

[+] File Permissions
--------------------

- Starting file permissions check
  File: /boot/grub2/grub.cfg                                [ OK ]
  File: /etc/at.deny                                        [ SUGGESTION ]
  File: /etc/cron.deny                                      [ OK ]
  File: /etc/crontab                                        [ SUGGESTION ]
  File: /etc/group                                          [ OK ]
  File: /etc/group-                                         [ OK ]
  File: /etc/hosts.allow                                    [ OK ]
  File: /etc/hosts.deny                                     [ OK ]
  File: /etc/issue                                          [ OK ]
  File: /etc/issue.net                                      [ OK ]
  File: /etc/motd                                           [ OK ]
  File: /etc/passwd                                         [ OK ]
  File: /etc/passwd-                                        [ OK ]
  File: /etc/ssh/sshd_config                                [ OK ]
  Directory: /root/.ssh                                     [ OK ]
  Directory: /etc/cron.d                                    [ SUGGESTION ]
  Directory: /etc/cron.daily                                [ SUGGESTION ]
  Directory: /etc/cron.hourly                               [ SUGGESTION ]
  Directory: /etc/cron.weekly                               [ SUGGESTION ]
  Directory: /etc/cron.monthly                              [ SUGGESTION ]

[+] Home directories
--------------------

- Permissions of home directories                           [ OK ]
- Ownership of home directories                             [ OK ]
- Checking shell history files                              [ OK ]

[+] Kernel Hardening
--------------------

- Comparing sysctl key pairs with scan profile
  - dev.tty.ldisc_autoload (exp: 0)                         [ DIFFERENT ]
  - fs.protected_fifos (exp: 2)                             [ DIFFERENT ]
  - fs.protected_hardlinks (exp: 1)                         [ OK ]
  - fs.protected_regular (exp: 2)                           [ DIFFERENT ]
  - fs.protected_symlinks (exp: 1)                          [ OK ]
  - fs.suid_dumpable (exp: 0)                               [ OK ]
  - kernel.core_uses_pid (exp: 1)                           [ OK ]
  - kernel.ctrl-alt-del (exp: 0)                            [ OK ]
  - kernel.dmesg_restrict (exp: 1)                          [ DIFFERENT ]
  - kernel.kptr_restrict (exp: 2)                           [ DIFFERENT ]
  - kernel.modules_disabled (exp: 1)                        [ DIFFERENT ]
  - kernel.perf_event_paranoid (exp: 3)                     [ DIFFERENT ]
  - kernel.randomize_va_space (exp: 2)                      [ OK ]
  - kernel.sysrq (exp: 0)                                   [ DIFFERENT ]
  - kernel.unprivileged_bpf_disabled (exp: 1)               [ DIFFERENT ]
  - kernel.yama.ptrace_scope (exp: 1 2 3)                   [ DIFFERENT ]
  - net.core.bpf_jit_harden (exp: 2)                        [ DIFFERENT ]
  - net.ipv4.conf.all.accept_redirects (exp: 0)             [ DIFFERENT ]
  - net.ipv4.conf.all.accept_source_route (exp: 0)          [ OK ]
  - net.ipv4.conf.all.bootp_relay (exp: 0)                  [ OK ]
  - net.ipv4.conf.all.forwarding (exp: 0)                   [ OK ]
  - net.ipv4.conf.all.log_martians (exp: 1)                 [ DIFFERENT ]
  - net.ipv4.conf.all.mc_forwarding (exp: 0)                [ OK ]
  - net.ipv4.conf.all.proxy_arp (exp: 0)                    [ OK ]
  - net.ipv4.conf.all.rp_filter (exp: 1)                    [ OK ]
  - net.ipv4.conf.all.send_redirects (exp: 0)               [ DIFFERENT ]
  - net.ipv4.conf.default.accept_redirects (exp: 0)         [ DIFFERENT ]
  - net.ipv4.conf.default.accept_source_route (exp: 0)      [ OK ]
  - net.ipv4.conf.default.log_martians (exp: 1)             [ DIFFERENT ]
  - net.ipv4.icmp_echo_ignore_broadcasts (exp: 1)           [ OK ]
  - net.ipv4.icmp_ignore_bogus_error_responses (exp: 1)     [ OK ]
  - net.ipv4.tcp_syncookies (exp: 1)                        [ OK ]
  - net.ipv4.tcp_timestamps (exp: 0 1)                      [ OK ]
  - net.ipv6.conf.all.accept_redirects (exp: 0)             [ DIFFERENT ]
  - net.ipv6.conf.all.accept_source_route (exp: 0)          [ OK ]
  - net.ipv6.conf.default.accept_redirects (exp: 0)         [ DIFFERENT ]
  - net.ipv6.conf.default.accept_source_route (exp: 0)      [ OK ]

[+] Hardening
-------------

    - Installed compiler(s)                                   [ FOUND ]
    - Installed malware scanner                               [ FOUND ]
    - Non-native binary formats                               [ NOT FOUND ]

[+] Custom tests
----------------

- Running custom tests...                                   [ NONE ]

[+] Plugins (phase 2)
---------------------

================================================================================

  -[ Lynis 3.1.1 Results ]-

Warnings (2):
-------------

  ! Couldn't find 2 responsive nameservers [NETW-2705]
      https://cisofy.com/lynis/controls/NETW-2705/

  ! All jails in Fail2ban are disabled [TOOL-5104]
    - Details  : /etc/fail2ban/jail.conf
      https://cisofy.com/lynis/controls/TOOL-5104/

Suggestions (39):
-----------------

* Version of Lynis outdated, consider upgrading to the latest version [LYNIS]
  https://cisofy.com/lynis/controls/LYNIS/
* If not required, consider explicit disabling of core dump in /etc/security/limits.conf file [KRNL-5820]
  https://cisofy.com/lynis/controls/KRNL-5820/
* Configure password hashing rounds in /etc/login.defs [AUTH-9230]
  https://cisofy.com/lynis/controls/AUTH-9230/
* Look at the locked accounts and consider removing them [AUTH-9284]
  https://cisofy.com/lynis/controls/AUTH-9284/
* Configure minimum password age in /etc/login.defs [AUTH-9286]
  https://cisofy.com/lynis/controls/AUTH-9286/
* Configure maximum password age in /etc/login.defs [AUTH-9286]
  https://cisofy.com/lynis/controls/AUTH-9286/
* Default umask in /etc/profile or /etc/profile.d/custom.sh could be more strict (e.g. 027) [AUTH-9328]
  https://cisofy.com/lynis/controls/AUTH-9328/
* To decrease the impact of a full /home file system, place /home on a separate partition [FILE-6310]
  https://cisofy.com/lynis/controls/FILE-6310/
* To decrease the impact of a full /tmp file system, place /tmp on a separate partition [FILE-6310]
  https://cisofy.com/lynis/controls/FILE-6310/
* To decrease the impact of a full /var file system, place /var on a separate partition [FILE-6310]
  https://cisofy.com/lynis/controls/FILE-6310/
* Disable drivers like USB storage when not used, to prevent unauthorized storage or data theft [USB-1000]
  https://cisofy.com/lynis/controls/USB-1000/
* Disable drivers like firewire storage when not used, to prevent unauthorized storage or data theft [STRG-1846]
  https://cisofy.com/lynis/controls/STRG-1846/
* Add the IP name and FQDN to /etc/hosts for proper name resolving [NAME-4404]
  https://cisofy.com/lynis/controls/NAME-4404/
* Check your resolv.conf file and fill in a backup nameserver if possible [NETW-2705]
  https://cisofy.com/lynis/controls/NETW-2705/
* Determine if protocol 'dccp' is really needed on this system [NETW-3200]
  https://cisofy.com/lynis/controls/NETW-3200/
* Determine if protocol 'sctp' is really needed on this system [NETW-3200]
  https://cisofy.com/lynis/controls/NETW-3200/
* Determine if protocol 'rds' is really needed on this system [NETW-3200]
  https://cisofy.com/lynis/controls/NETW-3200/
* Determine if protocol 'tipc' is really needed on this system [NETW-3200]
  https://cisofy.com/lynis/controls/NETW-3200/
* Check iptables rules to see which rules are currently not used [FIRE-4513]
  https://cisofy.com/lynis/controls/FIRE-4513/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : AllowTcpForwarding (set YES to NO)
    https://cisofy.com/lynis/controls/SSH-7408/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : ClientAliveCountMax (set 3 to 2)
    https://cisofy.com/lynis/controls/SSH-7408/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : LogLevel (set INFO to VERBOSE)
    https://cisofy.com/lynis/controls/SSH-7408/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : MaxAuthTries (set 6 to 3)
    https://cisofy.com/lynis/controls/SSH-7408/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : MaxSessions (set 10 to 2)
    https://cisofy.com/lynis/controls/SSH-7408/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : PermitRootLogin (set YES to (FORCED-COMMANDS-ONLY|NO|PROHIBIT-PASSWORD|WITHOUT-PASSWORD))
    https://cisofy.com/lynis/controls/SSH-7408/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : Port (set 22 to )
    https://cisofy.com/lynis/controls/SSH-7408/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : TCPKeepAlive (set YES to NO)
    https://cisofy.com/lynis/controls/SSH-7408/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : UseDNS (set YES to NO)
    https://cisofy.com/lynis/controls/SSH-7408/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : X11Forwarding (set YES to NO)
    https://cisofy.com/lynis/controls/SSH-7408/
* Consider hardening SSH configuration [SSH-7408]

  - Details  : AllowAgentForwarding (set YES to NO)
    https://cisofy.com/lynis/controls/SSH-7408/
* Enable logging to an external logging host for archiving purposes and additional protection [LOGG-2154]
  https://cisofy.com/lynis/controls/LOGG-2154/
* Add a legal banner to /etc/issue, to warn unauthorized users [BANN-7126]
  https://cisofy.com/lynis/controls/BANN-7126/
* Add legal banner to /etc/issue.net, to warn unauthorized users [BANN-7130]
  https://cisofy.com/lynis/controls/BANN-7130/
* Audit daemon is enabled with an empty ruleset. Disable the daemon or define rules [ACCT-9630]
  https://cisofy.com/lynis/controls/ACCT-9630/
* Install a file integrity tool to monitor changes to critical and sensitive files [FINT-4350]
  https://cisofy.com/lynis/controls/FINT-4350/
* Determine if automation tools are present for system management [TOOL-5002]
  https://cisofy.com/lynis/controls/TOOL-5002/
* Consider restricting file permissions [FILE-7524]

  - Details  : See screen output or log file
  - Solution : Use chmod to change file permissions
    https://cisofy.com/lynis/controls/FILE-7524/
* One or more sysctl values differ from the scan profile and could be tweaked [KRNL-6000]

  - Solution : Change sysctl value or disable test (skip-test=KRNL-6000:`<sysctl-key>`)
    https://cisofy.com/lynis/controls/KRNL-6000/
* Harden compilers like restricting access to root user only [HRDN-7222]
  https://cisofy.com/lynis/controls/HRDN-7222/

Follow-up:
----------

- Show details of a test (lynis show details TEST-ID)
- Check the logfile for all details (less /var/log/lynis.log)
- Read security controls texts (https://cisofy.com)
- Use --upload to upload data to central system (Lynis Enterprise users)

================================================================================

  Lynis security scan details:

  Hardening index : 65 [#############       ]
  Tests performed : 250
  Plugins enabled : 0

  Components:

- Firewall               [V]
- Malware scanner        [V]

  Scan mode:
  Normal [V]  Forensics [ ]  Integration [ ]  Pentest [ ]

  Lynis modules:

- Compliance status      [?]
- Security audit         [V]
- Vulnerability scan     [V]

  Files:

- Test and debug information      : /var/log/lynis.log
- Report data                     : /var/log/lynis-report.dat

================================================================================
  Notice: Lynis update available
  Current version : 311    Latest version : 314
===============================================

  Lynis 3.1.1

  Auditing, system hardening, and compliance for UNIX-based systems
  (Linux, macOS, BSD, and others)

  2007-2021, CISOfy - https://cisofy.com/lynis/
  Enterprise support available (compliance, plugins, interface and tools)

================================================================================

  [TIP]: Enhance Lynis audits by adding your settings to custom.prf (see /etc/lynis/default.prf for all settings)
