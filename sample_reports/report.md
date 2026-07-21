# 🛡 Claus Incident Response Toolkit

## Incident Response Report

**Generated:** 2026-07-21 18:11:40

---

## System Information

- **hostname:** claus-HP-Laptop-15-bs0xx
- **operating_system:** Linux
- **distribution:** Linux-6.8.0-124-generic-x86_64-with-glibc2.35
- **kernel:** 6.8.0-124-generic
- **architecture:** x86_64
- **processor:** x86_64
- **current_user:** claus
- **timestamp:** 2026-07-21 18:11:39

## Logged-in Users

- claus    tty2         2026-07-21 09:49 (tty2)

## System Uptime

```
18:11:39 up  9:20,  1 user,  load average: 0.63, 1.21, 1.43
```

## Running Processes

```
PID USER     %CPU %MEM COMMAND
      1 root      0.0  0.3 systemd
      2 root      0.0  0.0 kthreadd
      3 root      0.0  0.0 pool_workqueue_release
      4 root      0.0  0.0 kworker/R-rcu_g
      5 root      0.0  0.0 kworker/R-rcu_p
      6 root      0.0  0.0 kworker/R-slub_
      7 root      0.0  0.0 kworker/R-netns
      9 root      0.0  0.0 kworker/0:0H-events_highpri
     12 root      0.0  0.0 kworker/R-mm_pe
     13 root      0.0  0.0 rcu_tasks_kthread
     14 root      0.0  0.0 rcu_tasks_rude_kthread
     15 root      0.0  0.0 rcu_tasks_trace_kthread
     16 root      0.1  0.0 ksoftirqd/0
     17 root      0.0  0.0 rcu_preempt
     18 root      0.0  0.0 migration/0
     19 root      0.0  0.0 idle_inject/0
     20 root      0.0  0.0 cpuhp/0
     21 root      0.0  0.0 cpuhp/1
     22 root      0.0  0.0 idle_inject/1
     23 root      0.0  0.0 migration/1
     24 root      0.0  0.0 ksoftirqd/1
     26 root      0.0  0.0 kworker/1:0H-events_highpri
     29 root      0.0  0.0 kdevtmpfs
     30 root      0.0  0.0 kworker/R-inet_
     31 root      0.0  0.0 kauditd
     32 root      0.0  0.0 khungtaskd
     33 root      0.0  0.0 oom_reaper
     36 root      0.0  0.0 kworker/R-write
     37 root      0.0  0.0 kcompactd0
     38 root      0.0  0.0 ksmd
     40 root      0.0  0.0 khugepaged
     41 root      0.0  0.0 kworker/R-kinte
     42 root      0.0  0.0 kworker/R-kbloc
     43 root      0.0  0.0 kworker/R-blkcg
     44 root      0.0  0.0 irq/9-acpi
     45 root      0.0  0.0 kworker/R-tpm_d
     46 root      0.0  0.0 kworker/R-ata_s
     47 root      0.0  0.0 kworker/R-md
     48 root      0.0  0.0 kworker/R-md_bi
     49 root      0.0  0.0 kworker/R-edac-
     51 root      0.0  0.0 kworker/R-devfr
     52 root      0.0  0.0 watchdogd
     53 root      0.0  0.0 kworker/R-quota
     55 root      0.0  0.0 kworker/1:1H-kblockd
     56 root      0.0  0.0 kswapd0
     57 root      0.0  0.0 ecryptfs-kthread
     58 root      0.0  0.0 kworker/R-kthro
     59 root      0.0  0.0 kworker/R-acpi_
     62 root      0.0  0.0 kworker/R-mld
     63 root      0.0  0.0 kworker/R-ipv6_
     64 root      0.0  0.0 kworker/0:1H-events_highpri
     71 root      0.0  0.0 kworker/R-kstrp
     73 root      0.0  0.0 kworker/u11:0-hci0
     88 root      0.0  0.0 kworker/R-charg
    139 root      0.0  0.0 scsi_eh_0
    140 root      0.0  0.0 kworker/R-scsi_
    142 root      0.0  0.0 scsi_eh_1
    143 root      0.0  0.0 kworker/R-scsi_
    190 root      0.0  0.0 jbd2/sda2-8
    191 root      0.0  0.0 kworker/R-ext4-
    234 root      0.0  0.4 systemd-journal
    319 root      0.0  0.2 systemd-udevd
    343 root      0.0  0.0 irq/121-ACPI:Event
    350 root      0.0  0.0 irq/122-mei_txe
    352 root      0.0  0.0 irq/123-proc_thermal
    353 root      0.0  0.0 kworker/R-cfg80
    360 root      0.0  0.0 irq/124-iwlwifi
    367 root      0.0  0.0 kworker/R-crypt
    408 root      0.0  0.0 kworker/R-ttm
    409 root      0.0  0.0 card1-crtc0
    411 root      0.0  0.0 card1-crtc1
    412 root      0.0  0.0 card1-crtc2
    700 systemd+  0.5  0.1 systemd-oomd
    701 systemd+  0.0  0.3 systemd-resolve
    702 systemd+  0.0  0.1 systemd-timesyn
    805 root      0.0  0.2 accounts-daemon
    806 root      0.0  0.0 acpid
    809 avahi     0.0  0.1 avahi-daemon
    810 root      0.0  0.1 bluetoothd
    811 root      0.0  0.0 cron
    812 message+  0.0  0.1 dbus-daemon
    813 root      0.0  0.4 NetworkManager
    819 root      0.0  0.1 irqbalance
    820 root      0.0  0.5 networkd-dispat
    821 root      0.0  0.3 polkitd
    823 root      0.0  0.1 power-profiles-
    824 syslog    0.0  0.1 rsyslogd
    826 root      0.1  1.1 snapd
    827 root      0.0  0.1 switcheroo-cont
    828 root      0.0  0.2 systemd-logind
    829 root      0.0  0.2 thermald
    831 root      0.0  0.3 udisksd
    832 root      0.0  0.2 wpa_supplicant
    894 avahi     0.0  0.0 avahi-daemon
    955 root      0.0  0.3 cupsd
    960 root      0.0  0.6 unattended-upgr
    968 root      0.0  0.3 ModemManager
    983 root      0.2  1.2 containerd
   1001 root      0.0  0.2 gdm3
   1003 debian-+  0.0  1.2 tor
   1054 root      0.0  0.2 cups-browsed
   1065 kernoops  0.0  0.0 kerneloops
   1067 kernoops  0.0  0.0 kerneloops
   1129 rtkit     0.0  0.0 rtkit-daemon
   1214 root      0.0  2.1 dockerd
   1729 root      0.0  0.2 upowerd
   1736 root      0.1  1.9 packagekitd
   1936 colord    0.0  0.3 colord
   9773 root      0.0  0.2 gdm-session-wor
   9786 claus     0.0  0.3 systemd
   9789 claus     0.0  0.1 (sd-pam)
   9795 claus     0.0  0.1 pipewire
   9796 claus     0.0  0.1 pipewire-media-
   9797 claus     0.0  0.6 pulseaudio
   9806 claus     0.0  0.2 gnome-keyring-d
   9814 claus     0.0  0.1 gdm-wayland-ses
   9816 claus     0.0  0.1 dbus-daemon
   9825 claus     0.0  0.3 gnome-session-b
   9838 claus     0.0  0.1 xdg-document-po
   9842 claus     0.0  0.1 xdg-permission-
   9848 root      0.0  0.0 fusermount3
   9893 root      0.0  0.0 krfcommd
   9894 root      0.0  0.0 kworker/u11:1-hci0
   9908 claus     0.0  0.1 gnome-session-c
   9918 claus     0.0  0.1 gvfsd
   9923 claus     0.0  0.1 gvfsd-fuse
   9931 claus     0.0  0.4 gnome-session-b
   9957 claus     0.0  0.2 at-spi-bus-laun
   9966 claus     4.8  6.4 gnome-shell
   9968 claus     0.0  0.1 dbus-daemon
   9999 claus     0.0  0.4 gnome-shell-cal
  10007 claus     0.0  0.8 evolution-sourc
  10008 claus     0.0  0.1 dconf-service
  10017 claus     0.0  0.2 gvfs-udisks2-vo
  10023 claus     0.0  1.6 goa-daemon
  10025 claus     0.0  0.1 gvfs-mtp-volume
  10029 claus     0.0  0.1 gvfs-gphoto2-vo
  10033 claus     0.0  0.2 gvfs-afc-volume
  10038 claus     0.0  0.1 gvfs-goa-volume
  10041 claus     0.0  0.1 gvfsd-metadata
  10050 claus     0.0  1.0 evolution-calen
  10059 claus     0.0  0.3 goa-identity-se
  10074 claus     0.0  0.2 glib-pacrunner
  10080 claus     0.0  0.7 evolution-addre
  10092 claus     0.0  0.2 gvfsd-trash
  10107 claus     0.0  0.7 gjs
  10109 claus     0.0  0.1 at-spi2-registr
  10121 claus     0.0  0.0 sh
  10122 claus     0.0  0.1 gsd-a11y-settin
  10125 claus     0.3  0.3 ibus-daemon
  10126 claus     0.0  0.6 gsd-color
  10129 claus     0.0  0.3 gsd-datetime
  10135 claus     0.0  0.2 gsd-housekeepin
  10137 claus     0.0  0.5 gsd-keyboard
  10140 claus     0.0  0.6 gsd-media-keys
  10142 claus     0.0  0.6 gsd-power
  10145 claus     0.0  0.2 gsd-print-notif
  10151 claus     0.0  0.1 gsd-rfkill
  10155 claus     0.0  0.1 gsd-screensaver
  10156 claus     0.0  0.2 gsd-sharing
  10159 claus     0.0  0.2 gsd-smartcard
  10160 claus     0.0  0.2 gsd-disk-utilit
  10165 claus     0.0  0.2 gsd-sound
  10170 claus     0.0  0.5 gsd-wacom
  10183 claus     0.0  1.6 evolution-alarm
  10212 claus     0.0  0.1 ibus-memconf
  10215 claus     0.0  0.7 ibus-extension-
  10221 claus     0.0  0.3 gsd-printer
  10234 claus     0.0  0.1 ibus-portal
  10290 claus     0.0  4.5 snap-store
  10328 claus     0.1  0.1 ibus-engine-sim
  10374 claus     0.0  1.0 tracker-miner-f
  10390 claus     0.0  0.3 xdg-desktop-por
  10421 claus     0.0  0.7 gjs
  10424 claus     0.0  0.7 xdg-desktop-por
  10436 claus     0.0  1.5 gjs
  10520 claus     0.0  0.6 xdg-desktop-por
  10683 claus     0.0  0.7 update-notifier
  13198 claus     1.8  1.4 gnome-terminal-
  13216 claus     0.0  0.1 bash
  13230 claus     3.0  9.5 chrome
  13235 claus     0.0  0.0 cat
  13236 claus     0.0  0.0 cat
  13238 claus     0.0  0.1 chrome_crashpad
  13240 claus     0.0  0.0 chrome_crashpad
  13246 claus     0.0  1.6 chrome
  13247 claus     0.0  1.6 chrome
  13253 claus     0.0  0.4 chrome
  13282 claus    13.5  4.9 chrome
  13284 claus     0.0  2.0 Xwayland
  13301 claus     0.0  2.0 gsd-xsettings
  13325 claus     0.0  1.5 chrome
  13342 claus     0.0  0.6 ibus-x11
  13437 claus     0.0  3.3 chrome
  13446 claus     0.6  3.4 chrome
  13512 claus    51.7 11.6 chrome
  13529 claus     0.0  1.9 chrome
  13862 root      0.0  0.0 kworker/u8:1-ext4-rsv-conversion
  13985 root      0.4  0.0 kworker/0:0-i915-unordered
  14237 claus     0.0  0.1 user-session-he
  14422 root      0.0  0.0 kworker/u8:2-i915
  14438 claus     0.0  0.8 snapd-desktop-i
  14719 root      0.0  0.0 kworker/1:0-events
  14762 root      0.0  0.0 kworker/u9:0-flush-8:0
  14779 root      0.0  0.0 kworker/u10:3-events_power_efficient
  15055 root      0.1  0.0 kworker/u12:2-i915_flip
  15263 root      0.1  0.0 kworker/1:1-events
  15269 root      0.1  0.0 kworker/u13:2-i915_flip
  15273 root      0.0  0.0 kworker/0:2
  15350 root      0.0  0.0 kworker/u10:2-events_power_efficient
  15377 root      0.0  0.0 kworker/u9:3-flush-8:0
  15391 root      0.0  0.0 kworker/u10:0-events_unbound
  15406 claus     0.0  3.0 chrome
  15417 root      0.0  0.0 kworker/u12:0-rb_allocator
  15427 root      0.0  0.0 kworker/u9:2-events_unbound
  15428 root      0.0  0.0 kworker/u13:1-rb_allocator
  15459 root      0.0  0.0 kworker/u13:0-rb_allocator
  15463 root      0.0  0.0 kworker/u9:1-events_power_efficient
  15464 root      0.0  0.0 kworker/0:1
  15465 root      0.0  0.0 kworker/u12:1-i915_flip
  15468 root      0.0  0.0 kworker/u10:1-events_power_efficient
  15470 claus     0.0  0.5 python
  15474 claus     0.0  0.0 ps
```

## Listening Ports

```
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*          
udp   UNCONN 0      0            0.0.0.0:59667      0.0.0.0:*          
udp   UNCONN 0      0        224.0.0.251:5353       0.0.0.0:*          
udp   UNCONN 0      0            0.0.0.0:5353       0.0.0.0:*          
udp   UNCONN 0      0               [::]:49389         [::]:*          
udp   UNCONN 0      0               [::]:5353          [::]:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:40753      0.0.0.0:*          
tcp   LISTEN 0      128        127.0.0.1:631        0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:9050       0.0.0.0:*          
tcp   LISTEN 0      128            [::1]:631           [::]:*
```

## Network Connections

```
Netid State  Recv-Q Send-Q    Local Address:Port    Peer Address:PortProcess                            
udp   UNCONN 0      0         127.0.0.53%lo:53           0.0.0.0:*                                      
udp   ESTAB  0      0      172.20.10.3%wlo1:68       172.20.10.1:67                                     
udp   UNCONN 0      0               0.0.0.0:59667        0.0.0.0:*                                      
udp   UNCONN 0      0           224.0.0.251:5353         0.0.0.0:*    users:(("chrome",pid=13446,fd=36))
udp   UNCONN 0      0               0.0.0.0:5353         0.0.0.0:*                                      
udp   UNCONN 0      0                  [::]:49389           [::]:*                                      
udp   UNCONN 0      0                  [::]:5353            [::]:*                                      
tcp   LISTEN 0      4096      127.0.0.53%lo:53           0.0.0.0:*                                      
tcp   LISTEN 0      4096          127.0.0.1:40753        0.0.0.0:*                                      
tcp   LISTEN 0      128           127.0.0.1:631          0.0.0.0:*                                      
tcp   LISTEN 0      4096          127.0.0.1:9050         0.0.0.0:*                                      
tcp   ESTAB  0      0           172.20.10.3:48840    35.190.80.1:443  users:(("chrome",pid=13446,fd=25))
tcp   ESTAB  0      0           172.20.10.3:59016 172.64.155.209:443  users:(("chrome",pid=13446,fd=22))
tcp   ESTAB  0      0           172.20.10.3:35362 64.233.184.188:5228 users:(("chrome",pid=13446,fd=24))
tcp   ESTAB  0      0           172.20.10.3:37654 172.64.148.235:443  users:(("chrome",pid=13446,fd=29))
tcp   LISTEN 0      128               [::1]:631             [::]:*
```

## Running Services

```
UNIT                          LOAD   ACTIVE SUB     DESCRIPTION
  accounts-daemon.service       loaded active running Accounts Service
  acpid.service                 loaded active running ACPI event daemon
  avahi-daemon.service          loaded active running Avahi mDNS/DNS-SD Stack
  bluetooth.service             loaded active running Bluetooth service
  colord.service                loaded active running Manage, Install and Generate Color Profiles
  containerd.service            loaded active running containerd container runtime
  cron.service                  loaded active running Regular background program processing daemon
  cups-browsed.service          loaded active running Make remote CUPS printers available locally
  cups.service                  loaded active running CUPS Scheduler
  dbus.service                  loaded active running D-Bus System Message Bus
  docker.service                loaded active running Docker Application Container Engine
  gdm.service                   loaded active running GNOME Display Manager
  irqbalance.service            loaded active running irqbalance daemon
  kerneloops.service            loaded active running Tool to automatically collect and submit kernel crash signatures
  ModemManager.service          loaded active running Modem Manager
  networkd-dispatcher.service   loaded active running Dispatcher daemon for systemd-networkd
  NetworkManager.service        loaded active running Network Manager
  packagekit.service            loaded active running PackageKit Daemon
  polkit.service                loaded active running Authorization Manager
  power-profiles-daemon.service loaded active running Power Profiles daemon
  rsyslog.service               loaded active running System Logging Service
  rtkit-daemon.service          loaded active running RealtimeKit Scheduling Policy Service
  snapd.service                 loaded active running Snap Daemon
  switcheroo-control.service    loaded active running Switcheroo Control Proxy service
  systemd-journald.service      loaded active running Journal Service
  systemd-logind.service        loaded active running User Login Management
  systemd-oomd.service          loaded active running Userspace Out-Of-Memory (OOM) Killer
  systemd-resolved.service      loaded active running Network Name Resolution
  systemd-timesyncd.service     loaded active running Network Time Synchronization
  systemd-udevd.service         loaded active running Rule-based Manager for Device Events and Files
  thermald.service              loaded active running Thermal Daemon Service
  tor@default.service           loaded active running Anonymizing overlay network for TCP
  udisks2.service               loaded active running Disk Manager
  unattended-upgrades.service   loaded active running Unattended Upgrades Shutdown
  upower.service                loaded active running Daemon for power management
  user@1000.service             loaded active running User Manager for UID 1000
  wpa_supplicant.service        loaded active running WPA supplicant

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.
37 loaded units listed.
```

## Disk Usage

```
Filesystem      Size  Used Avail Use% Mounted on
tmpfs           383M  2.2M  380M   1% /run
/dev/sda2       457G   73G  361G  17% /
tmpfs           1.9G   24M  1.9G   2% /dev/shm
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
efivarfs        128K   97K   27K  79% /sys/firmware/efi/efivars
/dev/sda1       511M  6.1M  505M   2% /boot/efi
tmpfs           383M  120K  383M   1% /run/user/1000
```

## Memory Usage

```
total        used        free      shared  buff/cache   available
Mem:           3.7Gi       1.6Gi       533Mi       173Mi       1.6Gi       1.7Gi
Swap:          3.9Gi        24Mi       3.9Gi
```

## Network Interfaces

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eno1: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
    link/ether 48:ba:4e:b6:1d:4c brd ff:ff:ff:ff:ff:ff
    altname enp3s0
3: wlo1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether f8:94:c2:b6:70:ab brd ff:ff:ff:ff:ff:ff
    altname wlp2s0
    inet 172.20.10.3/28 brd 172.20.10.15 scope global dynamic noprefixroute wlo1
       valid_lft 83824sec preferred_lft 83824sec
    inet6 fe80::232a:4d42:198d:817/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
4: br-6cba48243dab: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether b6:96:31:72:0c:20 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-6cba48243dab
       valid_lft forever preferred_lft forever
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 9e:ae:ea:07:c9:e5 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
```

## Routing Table

```
default via 172.20.10.1 dev wlo1 proto dhcp metric 600 
169.254.0.0/16 dev br-6cba48243dab scope link metric 1000 linkdown 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown 
172.18.0.0/16 dev br-6cba48243dab proto kernel scope link src 172.18.0.1 linkdown 
172.20.10.0/28 dev wlo1 proto kernel scope link src 172.20.10.3 metric 600
```

