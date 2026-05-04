Last login: Thu Apr 23 12:48:49 on ttys014
ryu@Mac ~ %   nc -vuz 133.42.49.151 500

Connection to 133.42.49.151 port 500 [udp/isakmp] succeeded!
ryu@Mac ~ %nc -vuz 133.42.49.151 4500
Connection to 133.42.49.151 port 4500 [udp/ipsec-msft] succeeded!
ryu@Mac ~ %   log show --last 3m --predicate 'process == "racoon" OR process == "pppd"' --info | tail -50

Timestamp                       Thread     Type        Activity             PID    TTL  
2026-04-24 09:25:40.698510+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] Resend Phase 1 packet 535d2e83f8d7ad87:921e4d3b0bfbb83d
2026-04-24 09:25:40.851834+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:41.918965+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:42.986403+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:44.052305+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:45.117929+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:46.184629+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:47.251317+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:48.317930+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:49.384592+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:50.451268+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:51.518140+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:52.584584+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:53.497426+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] Resend Phase 1 packet 535d2e83f8d7ad87:921e4d3b0bfbb83d
2026-04-24 09:25:53.651200+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:54.717887+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:55.784880+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:56.849247+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:57.914516+0900 0x20eeab4  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:25:58.984965+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] CHKPH1THERE: no established ph1 handler found
2026-04-24 09:26:00.049761+0900 0x20eeab6  Error       0x0                  15495  0    racoon: [com.apple.networkextension:] Phase 2 negotiation failed due to time up waiting for Phase 1. ESP 133.42.49.151[4500]->172.20.10.3[4500]
2026-04-24 09:26:00.049764+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] delete Phase 2 handler.
2026-04-24 09:26:00.411888+0900 0x20eea5a  Default     0x0                  15493  0    pppd: [com.apple.networkextension:] IPSec connection failed
2026-04-24 09:26:00.413215+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] vpn_control socket closed by peer.
2026-04-24 09:26:00.413216+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] received disconnect all command.
2026-04-24 09:26:00.413234+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] IPSec disconnecting from server 133.42.49.151
2026-04-24 09:26:00.413236+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] in ike_session_purgephXbydstaddrwop... purging Phase 1 and related Phase 2 structures
2026-04-24 09:26:00.413657+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] ISAKMP-SA expired 172.20.10.3[4500]-133.42.49.151[4500] spi:535d2e83f8d7ad87:921e4d3b0bfbb83d
2026-04-24 09:26:00.413659+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] state changed to: Phase 1 expired
2026-04-24 09:26:00.413660+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] no ph1bind replacement found. NULL ph1.
2026-04-24 09:26:00.413676+0900 0x20eeab6  Default     0x0                  15495  0    racoon: [com.apple.networkextension:] vpncontrol_close_comm.
2026-04-24 09:26:00.418733+0900 0x20eea5a  Info        0x0                  15493  0    pppd: [com.apple.networkextension:] Exit.
2026-04-24 09:26:00.419085+0900 0x20eea5a  Default     0x0                  15493  0    pppd: (CoreAnalytics) [com.apple.CoreAnalytics:client] Entering exit handler.
2026-04-24 09:26:00.419088+0900 0x20eea5a  Default     0x0                  15493  0    pppd: (CoreAnalytics) [com.apple.CoreAnalytics:client] Queueing exit procedure onto XPC queue. Any further messages sent will be discarded. activeSendTransactions=0
2026-04-24 09:26:00.419347+0900 0x20eea62  Default     0x0                  15493  0    pppd: (CoreAnalytics) [com.apple.CoreAnalytics:client] Cancelling XPC connection. Any further reply handler invocations will not retry messages
2026-04-24 09:26:00.419817+0900 0x20eea62  Default     0x0                  15493  0    pppd: (libxpc.dylib) [com.apple.xpc:connection] [0x10520f400] invalidated because the current process cancelled the connection by calling xpc_connection_cancel()
2026-04-24 09:26:00.419884+0900 0x20eea5a  Default     0x0                  15493  0    pppd: (CoreAnalytics) [com.apple.CoreAnalytics:client] Exiting exit handler.
2026-04-24 09:26:03.646725+0900 0x20eeab4  Default     0x0                  15495  0    racoon: (CoreAnalytics) [com.apple.CoreAnalytics:client] Entering exit handler.
2026-04-24 09:26:03.646735+0900 0x20eeab4  Default     0x0                  15495  0    racoon: (CoreAnalytics) [com.apple.CoreAnalytics:client] Queueing exit procedure onto XPC queue. Any further messages sent will be discarded. activeSendTransactions=0
2026-04-24 09:26:03.647057+0900 0x20eeab6  Default     0x0                  15495  0    racoon: (CoreAnalytics) [com.apple.CoreAnalytics:client] Cancelling XPC connection. Any further reply handler invocations will not retry messages
2026-04-24 09:26:03.647064+0900 0x20eeab6  Default     0x0                  15495  0    racoon: (libxpc.dylib) [com.apple.xpc:connection] [0x1031a3090] invalidated because the current process cancelled the connection by calling xpc_connection_cancel()
2026-04-24 09:26:03.647813+0900 0x20eeab4  Default     0x0                  15495  0    racoon: (CoreAnalytics) [com.apple.CoreAnalytics:client] Exiting exit handler.
ryu@Mac ~ %
ryu@Mac ~ %ifconfig ppp0 | grep inet
	inet6 fe80::129f:41ff:fec8:dc1b%ppp0 prefixlen 64 scopeid 0x1b 
	inet 10.1.16.24 --> 192.168.100.244 netmask 0xff000000
ryu@Mac ~ %netstat -rn | grep 10.1
default            172.20.10.1        UGScIg                en0       
133.42.49.151      172.20.10.1        UGHS                  en0       
172.20.10.1/32     link#11            UCS                   en0      !
172.20.10.1        2:92:35:9d:b7:64   UHLWIir               en0   1154
172.20.10.15       ff:ff:ff:ff:ff:ff  UHLWbI                en0      !
192.168.100.244    10.1.16.24         UH                   ppp0       
ryu@Mac ~ %ping -c 3 10.1.6.1
PING 10.1.6.1 (10.1.6.1): 56 data bytes
64 bytes from 10.1.6.1: icmp_seq=0 ttl=61 time=79.296 ms
64 bytes from 10.1.6.1: icmp_seq=1 ttl=61 time=51.819 ms
64 bytes from 10.1.6.1: icmp_seq=2 ttl=61 time=66.099 ms

--- 10.1.6.1 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 51.819/65.738/79.296/11.220 ms
ryu@Mac ~ %ping -c 3 10.1.6.2
PING 10.1.6.2 (10.1.6.2): 56 data bytes
64 bytes from 10.1.6.2: icmp_seq=0 ttl=61 time=115.013 ms
64 bytes from 10.1.6.2: icmp_seq=1 ttl=61 time=62.052 ms
64 bytes from 10.1.6.2: icmp_seq=2 ttl=61 time=56.739 ms

--- 10.1.6.2 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 56.739/77.935/115.013/26.308 ms
ryu@Mac ~ %ssh manage@10.1.6.1

The authenticity of host '10.1.6.1 (10.1.6.1)' can't be established.
ED25519 key fingerprint is SHA256:2hFd5utNHZ6RYRKFkiyLmwRBHtrkKWE6f09YbsK0s3M.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.1.6.1' (ED25519) to the list of known hosts.
(manage@10.1.6.1) Password for manage@bravo.com6.local:
Last login: Fri Apr 24 08:53:49 2026 from 10.1.16.12
FreeBSD 14.3-RELEASE (GENERIC) releng/14.3-n271432-8c9ce319fef7

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List:        https://www.FreeBSD.org/lists/questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

To change this login announcement, see motd(5).
> bash
[manage@bravo ~]$ freebsd-version
14.3-RELEASE
[manage@bravo ~]$ uname -a
FreeBSD bravo.com6.local 14.3-RELEASE FreeBSD 14.3-RELEASE releng/14.3-n271432-8c9ce319fef7 GENERIC amd64
[manage@bravo ~]$ hostname
bravo.com6.local
[manage@bravo ~]$ uptime
 9:41午前  up 4 days, 14:48, 1 user, load averages: 0.05, 0.06, 0.07
[manage@bravo ~]$ service -e
/etc/rc.d/hostid
/etc/rc.d/hostid_save
/etc/rc.d/var_run
/etc/rc.d/kldxref
/etc/rc.d/devmatch
/etc/rc.d/cleanvar
/etc/rc.d/ip6addrctl
/etc/rc.d/rctl
/etc/rc.d/mixer
/etc/rc.d/netif
/etc/rc.d/devd
/etc/rc.d/resolv
/etc/rc.d/motd
/etc/rc.d/newsyslog
/etc/rc.d/cleartmp
/etc/rc.d/dmesg
/etc/rc.d/virecover
/etc/rc.d/os-release
/etc/rc.d/gptboot
/etc/rc.d/syslogd
/usr/local/etc/rc.d/named
/etc/rc.d/ntpdate
/etc/rc.d/savecore
/etc/rc.d/utx
/etc/rc.d/ntpd
/etc/rc.d/inetd
/usr/local/etc/rc.d/mysql-server
/etc/rc.d/sshd
/etc/rc.d/cron
/etc/rc.d/bgfsck
/usr/local/etc/rc.d/apache24
/usr/local/etc/rc.d/courier-authdaemond
/usr/local/etc/rc.d/courier-imap-imapd
/etc/rc.d/sendmail
[manage@bravo ~]$ ps auxwww | grep -Ei 'httpd|nginx|apache|named|postfix' | grep -v grep
bind     641   0.0  0.4   57812  18068  -  Is   日18       0:00.72 /usr/local/sbin/named -u bind -c /usr/local/etc/namedb/named.conf
root    1985   0.0  0.6  180300  25700  -  Ss   日18       0:06.58 /usr/local/sbin/httpd
www     2023   0.0  0.7  180300  29964  -  S    日18       0:00.12 /usr/local/sbin/httpd
www     2024   0.0  0.7  180300  29964  -  I    日18       0:00.00 /usr/local/sbin/httpd
www     2026   0.0  0.7  180300  29976  -  I    日18       0:00.00 /usr/local/sbin/httpd
www     2027   0.0  0.7  180300  29976  -  I    日18       0:00.00 /usr/local/sbin/httpd
www     9632   0.0  0.7  180300  29964  -  I    月18       0:00.00 /usr/local/sbin/httpd
www     9635   0.0  0.7  180300  29976  -  I    月18       0:00.01 /usr/local/sbin/httpd
www     9636   0.0  0.7  180300  29964  -  I    月18       0:00.00 /usr/local/sbin/httpd
www     9638   0.0  0.7  180300  29976  -  I    月18       0:00.00 /usr/local/sbin/httpd
www    10280   0.0  0.7  180300  30088  -  I    月20       0:00.23 /usr/local/sbin/httpd
www    10282   0.0  0.7  180300  29964  -  I    月20       0:00.00 /usr/local/sbin/httpd
[manage@bravo ~]$ sockstat -4 -l
USER     COMMAND    PID   FD  PROTO  LOCAL ADDRESS         FOREIGN ADDRESS      
www      httpd      10282 4   tcp4   *:80                  *:*
www      httpd      10280 4   tcp4   *:80                  *:*
www      httpd       9638 4   tcp4   *:80                  *:*
www      httpd       9636 4   tcp4   *:80                  *:*
www      httpd       9635 4   tcp4   *:80                  *:*
www      httpd       9632 4   tcp4   *:80                  *:*
root     sendmail    2028 4   tcp4   *:25                  *:*
www      httpd       2027 4   tcp4   *:80                  *:*
www      httpd       2026 4   tcp4   *:80                  *:*
www      httpd       2024 4   tcp4   *:80                  *:*
www      httpd       2023 4   tcp4   *:80                  *:*
root     couriertcp  2020 3   tcp46  *:143                 *:*
root     httpd       1985 4   tcp4   *:80                  *:*
mysql    mysqld      1963 28  tcp46  *:33060               *:*
mysql    mysqld      1963 31  tcp4   127.0.0.1:3306        *:*
root     sshd         749 8   tcp4   *:22                  *:*
ntpd     ntpd         696 21  udp4   *:123                 *:*
ntpd     ntpd         696 22  udp4   10.1.6.1:123          *:*
ntpd     ntpd         696 25  udp4   127.0.0.1:123         *:*
bind     named        641 18  udp4   10.1.6.1:53           *:*
bind     named        641 19  udp4   10.1.6.1:53           *:*
bind     named        641 20  tcp4   10.1.6.1:53           *:*
bind     named        641 22  tcp4   10.1.6.1:53           *:*
bind     named        641 32  udp4   127.0.0.1:53          *:*
bind     named        641 33  udp4   127.0.0.1:53          *:*
bind     named        641 34  tcp4   127.0.0.1:53          *:*
bind     named        641 35  tcp4   127.0.0.1:53          *:*
bind     named        641 37  tcp4   127.0.0.1:953         *:*
root     syslogd      624 7   udp4   *:514                 *:*
[manage@bravo ~]$ netstat -an -p tcp | grep LISTEN
tcp6       0      0 *.25                   *.*                    LISTEN     
tcp4       0      0 *.25                   *.*                    LISTEN     
tcp46      0      0 *.143                  *.*                    LISTEN     
tcp4       0      0 *.80                   *.*                    LISTEN     
tcp6       0      0 *.80                   *.*                    LISTEN     
tcp4       0      0 127.0.0.1.3306         *.*                    LISTEN     
tcp46      0      0 *.33060                *.*                    LISTEN     
tcp4       0      0 *.22                   *.*                    LISTEN     
tcp6       0      0 *.22                   *.*                    LISTEN     
tcp6       0      0 ::1.953                *.*                    LISTEN     
tcp4       0      0 127.0.0.1.953          *.*                    LISTEN     
tcp4       0      0 127.0.0.1.53           *.*                    LISTEN     
tcp4       0      0 127.0.0.1.53           *.*                    LISTEN     
tcp6       0      0 fe80::1%lo0.53         *.*                    LISTEN     
tcp6       0      0 fe80::1%lo0.53         *.*                    LISTEN     
tcp6       0      0 ::1.53                 *.*                    LISTEN     
tcp6       0      0 ::1.53                 *.*                    LISTEN     
tcp4       0      0 10.1.6.1.53            *.*                    LISTEN     
tcp4       0      0 10.1.6.1.53            *.*                    LISTEN     
[manage@bravo ~]$ ls /usr/local/etc/apache24/ 2>/dev/null
envvars.d		Includes		mime.types.sample
extra			magic			modules.d
httpd.conf		magic.sample
httpd.conf.sample	mime.types
[manage@bravo ~]$ ls /usr/local/etc/nginx/ 2>/dev/null
[manage@bravo ~]$ ls /usr/local/www/ 2>/dev/null
apache24
[manage@bravo ~]$ ls /var/log/
auth.log		maillog			security
bsdinstall_log		maillog.0.bz2		sendmail.st
cron			maillog.1.bz2		sendmail.st.0
daemon.log		maillog.2.bz2		setuid.today
debug.log		maillog.3.bz2		setuid.yesterday
devd.log		maillog.4.bz2		userlog
dmesg.today		messages		utx.lastlogin
dmesg.yesterday		mount.today		utx.log
httpd-access.log	mount.yesterday		xferlog
httpd-error.log		mysql
lpd-errs		ppp.log
[manage@bravo ~]$ ls /var/log/ | grep -iE 'http|nginx|access|error'
httpd-access.log
httpd-error.log
[manage@bravo ~]$ sudo pfctl -s info 2>/dev/null
パスワード: 
[manage@bravo ~]$ ls /etc/apache2/ 2>/dev/null
[manage@bravo ~]$ ls /usr/local/etc/apache24/ 2>/dev/null
envvars.d		Includes		mime.types.sample
extra			magic			modules.d
httpd.conf		magic.sample
httpd.conf.sample	mime.types
[manage@bravo ~]$ ls /etc/nginx/ 2>/dev/null
[manage@bravo ~]$ ls /var/log/httpd/ 2>/dev/null
[manage@bravo ~]$ ls /var/log/apache2/ 2>/dev/null
[manage@bravo ~]$ ls /var/log/nginx/ 2>/dev/null
[manage@bravo ~]$ ls /var/log/httpd-*.log 2>/dev/null 
/var/log/httpd-access.log	/var/log/httpd-error.log
[manage@bravo ~]$ command -v firewall-cmd >/dev/null && sudo firewall-cmd --state 2>/dev/null
[manage@bravo ~]$ command -v ufw >/dev/null && sudo ufw status 2>/dev/null
[manage@bravo ~]$ command -v pfctl >/dev/null && sudo pfctl -s info 2>/dev/null
パスワード: 
[manage@bravo ~]$ ip -br a 2>/dev/null || ifconfig
vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	options=4c07bb<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,JUMBO_MTU,VLAN_HWCSUM,TSO4,TSO6,LRO,VLAN_HWTSO,LINKSTATE,TXCSUM_IPV6>
	ether bc:24:11:6a:e4:09
	inet 10.1.6.1 netmask 0xffffff00 broadcast 10.1.6.255
	media: Ethernet autoselect (10Gbase-T <full-duplex>)
	status: active
	nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
	options=680003<RXCSUM,TXCSUM,LINKSTATE,RXCSUM_IPV6,TXCSUM_IPV6>
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x2
	groups: lo
	nd6 options=21<PERFORMNUD,AUTO_LINKLOCAL>
[manage@bravo ~]$ ip -br r 2>/dev/null || netstat -rn
Routing tables

Internet:
Destination        Gateway            Flags         Netif Expire
default            10.1.6.254         UGS          vtnet0
10.1.6.0/24        link#1             U            vtnet0
10.1.6.1           link#2             UHS             lo0
127.0.0.1          link#2             UH              lo0

Internet6:
Destination                       Gateway                       Flags         Netif Expire
::/96                             link#2                        URS             lo0
::1                               link#2                        UHS             lo0
::ffff:0.0.0.0/96                 link#2                        URS             lo0
fe80::%lo0/10                     link#2                        URS             lo0
fe80::%lo0/64                     link#2                        U               lo0
fe80::1%lo0                       link#2                        UHS             lo0
ff02::/16                         link#2                        URS             lo0
[manage@bravo ~]$ cat /etc/resolv.conf
domain com6.local
nameserver 10.1.6.1



[manage@bravo ~]$ cat /etc/hosts
#
# Host Database
#
# This file should contain the addresses and aliases for local hosts that
# share this file.  Replace 'my.domain' below with the domainname of your
# machine.
#
# In the presence of the domain name service or NIS, this file may
# not be consulted at all; see /etc/nsswitch.conf for the resolution order.
#
#
::1			localhost localhost.com6.local
127.0.0.1		localhost localhost.com6.local
#
# Imaginary network.
10.1.6.1		bravo.com6.local bravo
10.1.6.1		bravo.com6.local.
#
# According to RFC 1918, you can use the following IP blocks for
# private internets:
#
#	10.0.0.0	-   10.255.255.255	(10/8 prefix)
#	172.16.0.0	-   172.31.255.255	(172.16/12 prefix)
#	192.168.0.0	-   192.168.255.255	(192.168/16 prefix)
#
# In case you want to make addresses available on the Internet, you need
# real official assigned numbers.  Do not try to invent your own network
# numbers but instead get one from your network provider (if any) or
# from your regional registry (ARIN, APNIC, LACNIC, RIPE NCC, or AfriNIC.)
#
[manage@bravo ~]$ grep -RslE '10\.1\.[0-9]+\.[0-9]+' /etc 2>/dev/null | head
/etc/hosts
/etc/rc.conf
/etc/resolv.conf
[manage@bravo ~]$ cut -d: -f1,3 /etc/passwd
root:0
toor:0
daemon:1
operator:2
bin:3
tty:4
kmem:5
games:7
news:8
man:9
sshd:22
smmsp:25
mailnull:26
bind:53
unbound:59
proxy:62
_pflogd:64
_dhcp:65
uucp:66
pop:68
auditdistd:78
www:80
ntpd:123
_ypldap:160
hast:845
tests:977
nobody:65534
cyrus:60
mysql:88
courier:465
adachi:1002
akai:1003
akiuchi:1004
akizuki:1005
chiba:1006
chikushi:1007
eda:1008
ezaki:1009
hamaguchi:1010
hamasaki:1011
hanai:1012
heguri:1013
hirata:1014
hisatomi:1015
hishinuma:1016
hoshida:1017
hotei:1018
hozumi:1019
hukuda:1020
hukumori:1021
hunaki:1022
huruhashi:1023
ikeda:1024
inamoto:1025
inoue:1026
itoda:1027
kaibara:1028
kanehara:1029
kanno:1030
kashiwagi:1031
katsura:1032
kawasaki:1033
kimura:1034
kine:1035
kiyohara:1036
kojima:1037
konoike:1038
kubo:1039
kumada:1040
kuramoto:1041
kushiro:1042
marui:1043
masuko:1044
matoba:1045
matsuda:1046
mitsuno:1047
mizumoto:1048
mochida:1049
morino:1050
muratani:1051
muta:1052
nakano:1053
natsume:1054
negoro:1055
nishida:1056
nishimoto:1057
noda:1058
noma:1059
okamoto:1060
ono:1061
saito:1062
saka:1063
sakoda:1064
sasano:1065
sato:1066
seike:1067
seko:1068
shiozaki:1069
shiraishi:1070
simada:1071
sinke:1072
soga:1073
sonoda:1074
sudou:1075
sumida:1076
sumiyoshi:1077
tabuchi:1078
takasago:1079
tanaka:1080
tanoue:1081
tebira:1082
terauchi:1083
toda:1084
tsuda:1085
tsukagoe:1086
tsukuba:1087
uemura:1088
ueno:1089
umeki:1090
utsunomiya:1091
wada:1092
yamaoka:1093
yamashita:1094
yano:1095
yasuda:1096
yasukawa:1097
yokota:1098
yokoyama:1099
yukawa:1100
yuno:1101
obuchi:1102
manage:1103
git_daemon:964
[manage@bravo ~]$ ls /etc/cron.d/ /etc/cron.daily/ 2>/dev/null
/etc/cron.d/:
at
[manage@bravo ~]$ cat /etc/crontab 2>/dev/null
# /etc/crontab - root's crontab for FreeBSD
#
#
SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
#
#minute	hour	mday	month	wday	who	command
#
# Save some entropy so that /dev/random can re-seed on boot.
*/11	*	*	*	*	operator /usr/libexec/save-entropy
#
# Rotate log files every hour, if necessary.
0	*	*	*	*	root	newsyslog
#
# Perform daily/weekly/monthly maintenance.
1	3	*	*	*	root	periodic daily
15	4	*	*	6	root	periodic weekly
30	5	1	*	*	root	periodic monthly
#
# Adjust the time zone if the CMOS clock keeps local time, as opposed to
# UTC time.  See adjkerntz(8) for details.
1,31	0-5	*	*	*	root	adjkerntz -a
[manage@bravo ~]$ id
uid=1103(manage) gid=1103(manage) groups=1103(manage),0(wheel)
[manage@bravo ~]$ groups
manage wheel
[manage@bravo ~]$ cat /etc/group | grep -E 'wheel|operator'
wheel:*:0:root,manage
operator:*:5:root
[manage@bravo ~]$ cat /usr/local/etc/apache24/httpd.conf | grep -E 'DocumentRoot|VirtualHost|Listen|ServerName|Include' | grep -v '^#'
Listen 80
IncludeOptional etc/apache24/modules.d/[0-9][0-9][0-9]_*.conf
DocumentRoot "/usr/local/www/apache24/data"
    #   Indexes Includes FollowSymLinks SymLinksifOwnerMatch ExecCGI MultiViews
    # If you do not define any access logfiles within a <VirtualHost>
    # define per-<VirtualHost> access logfiles, transactions will be
    # access content that does not live under the DocumentRoot.
    # (You will also need to add "Includes" to the "Options" directive.)
Include etc/apache24/extra/httpd-vhosts.conf
Include etc/apache24/extra/proxy-html.conf
Include etc/apache24/Includes/*.conf
[manage@bravo ~]$ ls /usr/local/etc/apache24/Includes/
no-accf.conf
[manage@bravo ~]$ ls /usr/local/etc/apache24/extra/
httpd-autoindex.conf			httpd-mpm.conf
httpd-autoindex.conf.sample		httpd-mpm.conf.sample
httpd-dav.conf				httpd-multilang-errordoc.conf
httpd-dav.conf.sample			httpd-multilang-errordoc.conf.sample
httpd-default.conf			httpd-ssl.conf
httpd-default.conf.sample		httpd-ssl.conf.sample
httpd-info.conf				httpd-userdir.conf
httpd-info.conf.sample			httpd-userdir.conf.sample
httpd-languages.conf			httpd-vhosts.conf
httpd-languages.conf.sample		httpd-vhosts.conf.sample
httpd-manual.conf			proxy-html.conf
httpd-manual.conf.sample		proxy-html.conf.sample
[manage@bravo ~]$ cat /usr/local/etc/apache24/Includes/*.conf 2>/dev/null
<IfDefine NOHTTPACCEPT>
   AcceptFilter http none
   AcceptFilter https none
</IfDefine>
[manage@bravo ~]$ ls /usr/local/www/apache24/
backup_data	cgi-bin		data		error		icons
[manage@bravo ~]$ ls /usr/local/www/apache24/data/ 2>/dev/null
include		index.php	StyleSheet.css
[manage@bravo ~]$ ls /usr/local/www/ -la
ls: -la: そのようなファイルまたはディレクトリはありません
/usr/local/www/:
apache24
[manage@bravo ~]$ cat /usr/local/etc/namedb/named.conf | head -80

options {
        directory       "/usr/local/etc/namedb/working";
        pid-file        "/var/run/named/pid";
        dump-file       "/var/dump/named_dump.db";
        statistics-file "/var/stats/named.stats";

        listen-on       { any; };
        forwarders {
                10.1.130.1;
        };
        allow-query {
                10.0.0.0/8;
        };
        allow-update {
                10.0.0.0/8;
        };
	dnssec-validation no;
};

zone "." { type hint; file "/usr/local/etc/namedb/named.root"; };

zone "com6.local" {
        type master;
        file "../primary/com6.local.zone";
        notify yes;
        allow-transfer {
                10.1.130.1;
        };
        also-notify{
                10.1.130.1;
        };
};
zone "6.1.10.in-addr.arpa" {
        type master;
        file "../primary/6.1.10.in-addr.arpa";
        notify yes;
        allow-transfer {
                10.1.130.1;
        };
        also-notify{
                10.1.130.1;
        };
};
zone "service.com6.local" {
        type master;
        file "../primary/service.com6.local.zone";
        notify yes;
        allow-transfer {
                10.1.130.1;
        };
        also-notify{
                10.1.130.1;
        };
};
zone "130.1.10.in-addr.arpa" {
	type forward;
	forward only;
	forwarders {
		10.1.130.1;
	};
};
[manage@bravo ~]$ ls /usr/local/etc/namedb/
dynamic			named.root		secondary
named.conf		primary			working
named.conf.sample	rndc.key
[manage@bravo ~]$ ls /usr/local/etc/namedb/master/ 2>/dev/null
[manage@bravo ~]$ cat /etc/mail/sendmail.cf 2>/dev/null | head -20
#
# Copyright (c) 1998-2004, 2009, 2010 Proofpoint, Inc. and its suppliers.
#	All rights reserved.
# Copyright (c) 1983, 1995 Eric P. Allman.  All rights reserved.
# Copyright (c) 1988, 1993
#	The Regents of the University of California.  All rights reserved.
#
# By using this file, you agree to the terms and conditions set
# forth in the LICENSE file which can be found at the top level of
# the sendmail distribution.
#
# $FreeBSD$
#

######################################################################
######################################################################
#####
#####		SENDMAIL CONFIGURATION FILE
#####
##### built by root@bravo.com1.local
[manage@bravo ~]$ ls /etc/mail/
access				freebsd.submit.mc
access.db			helpfile
access.sample			local-host-names
aliases				mailer.conf
aliases.db			mailertable.sample
bravo.com1.local.submit.cf	Makefile
bravo.com1.local.submit.mc	README
certs				sendmail.cf
freebsd.cf			sendmail.mc
freebsd.mc			submit.cf
freebsd.submit.cf		virtusertable.sample
[manage@bravo ~]$ ls /usr/local/etc/courier-imap/ 2>/dev/null
imapaccess		imapd-ssl.dist		pop3d-ssl.dist
imapaccess.dat		imapd.cnf		pop3d.cnf.dist
imapd			imapd.cnf.dist		pop3d.dist
imapd-e			imapd.dist		quotawarnmsg.example
imapd-ssl		pop3d			shared
imapd-ssl-e		pop3d-ssl		shared.tmp
[manage@bravo ~]$ cat /usr/local/etc/courier-imap/imapd 2>/dev/null | head -20
[manage@bravo ~]$ ls /var/db/mysql/ 2>/dev/null
#ib_16384_0.dblwr	private_key.pem		sb_blog_34
#ib_16384_1.dblwr	public_key.pem		sb_blog_35
#innodb_redo		sb_blog_1		sb_blog_36
#innodb_temp		sb_blog_10		sb_blog_37
adachi_bbs_db		sb_blog_11		sb_blog_38
auto.cnf		sb_blog_12		sb_blog_39
bravo-slow.log		sb_blog_13		sb_blog_4
bravo.com1.local.err	sb_blog_14		sb_blog_40
bravo.com6.local.err	sb_blog_15		sb_blog_41
bravo.com6.local.pid	sb_blog_16		sb_blog_42
ca-key.pem		sb_blog_17		sb_blog_43
ca.pem			sb_blog_18		sb_blog_44
client-cert.pem		sb_blog_19		sb_blog_45
client-key.pem		sb_blog_2		sb_blog_46
ib_buffer_pool		sb_blog_20		sb_blog_47
ibdata1			sb_blog_21		sb_blog_48
ibtmp1			sb_blog_22		sb_blog_49
mitsuno_bbs_db		sb_blog_23		sb_blog_5
mysql			sb_blog_24		sb_blog_50
mysql-bin.000008	sb_blog_25		sb_blog_6
mysql-bin.000009	sb_blog_26		sb_blog_7
mysql-bin.000010	sb_blog_27		sb_blog_8
mysql-bin.000011	sb_blog_28		sb_blog_9
mysql-bin.000012	sb_blog_29		server-cert.pem
mysql-bin.000013	sb_blog_3		server-key.pem
mysql-bin.index		sb_blog_30		sys
mysql.ibd		sb_blog_31		undo_001
oction			sb_blog_32		undo_002
performance_schema	sb_blog_33
[manage@bravo ~]$ cat /usr/local/etc/mysql/my.cnf 2>/dev/null | head -20
[client]
port                            = 3306
socket                          = /tmp/mysql.sock

[mysql]
#default-character-set		= utf8
prompt                          = \u@\h [\d]>\_
no_auto_rehash

[mysqld]
character-set-server		= utf8
default_authentication_plugin	= mysql_native_password
user                            = mysql
port                            = 3306
socket                          = /tmp/mysql.sock
bind-address                    = 127.0.0.1
basedir                         = /usr/local
datadir                         = /var/db/mysql
tmpdir                          = /var/db/mysql_tmpdir
replica-load-tmpdir             = /var/db/mysql_tmpdir
[manage@bravo ~]$ kldstat | grep -iE 'pf|ipfw'
[manage@bravo ~]$ cat /etc/rc.conf | grep -iE 'pf|firewall'
[manage@bravo ~]$ ls /etc/pf.conf 2>/dev/null
[manage@bravo ~]$ exit
exit
> ssh manage@10.1.6.2
The authenticity of host '10.1.6.2 (10.1.6.2)' can't be established.
RSA key fingerprint is SHA256:u901ZcofUG+EIVef1+SbAb0+JqPSuSrFzkgiuOrwyWw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.1.6.2' (RSA) to the list of known hosts.
manage@10.1.6.2's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Fri Apr 24 08:37:13 2026 from 10.1.16.16
[manage@victor ~]$ exit
ログアウト
Connection to 10.1.6.2 closed.
> ssh manage@10.1.6.1
The authenticity of host '10.1.6.1 (10.1.6.1)' can't be established.
RSA key fingerprint is SHA256:MTfuNM5/0ImUuulGrHfmTysHrC9JYpNjSFu+bCGQWQY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.1.6.1' (RSA) to the list of known hosts.
(manage@10.1.6.1) Password for manage@bravo.com6.local:
Last login: Fri Apr 24 09:45:02 2026 from 10.1.16.12
FreeBSD 14.3-RELEASE (GENERIC) releng/14.3-n271432-8c9ce319fef7

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List:        https://www.FreeBSD.org/lists/questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

To change this login announcement, see motd(5).
> bash
[manage@bravo ~]$ dig @10.1.6.1 victor.com6.local 2>/dev/null

; <<>> DiG 9.20.20 <<>> @10.1.6.1 victor.com6.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 34953
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 1cf6cf20b39a85010100000069eabf7218fb2113fb4cc118 (good)
;; QUESTION SECTION:
;victor.com6.local.		IN	A

;; ANSWER SECTION:
victor.com6.local.	180	IN	A	10.1.6.2

;; Query time: 0 msec
;; SERVER: 10.1.6.1#53(10.1.6.1) (UDP)
;; WHEN: Fri Apr 24 09:55:14 JST 2026
;; MSG SIZE  rcvd: 90

[manage@bravo ~]$ dig @10.1.6.1 bravo.com6.local 2>/dev/null

; <<>> DiG 9.20.20 <<>> @10.1.6.1 bravo.com6.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38780
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 84e0883443b358170100000069eabf757c550aa7141c7797 (good)
;; QUESTION SECTION:
;bravo.com6.local.		IN	A

;; ANSWER SECTION:
bravo.com6.local.	180	IN	A	10.1.6.1

;; Query time: 0 msec
;; SERVER: 10.1.6.1#53(10.1.6.1) (UDP)
;; WHEN: Fri Apr 24 09:55:17 JST 2026
;; MSG SIZE  rcvd: 89

[manage@bravo ~]$ dig @10.1.6.1 com6.local ANY 2>/dev/null

; <<>> DiG 9.20.20 <<>> @10.1.6.1 com6.local ANY
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2048
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 34900d637fb274710100000069eabf782d05e3afe0f91ace (good)
;; QUESTION SECTION:
;com6.local.			IN	ANY

;; ANSWER SECTION:
com6.local.		180	IN	A	10.1.6.1
com6.local.		180	IN	SOA	ns.com6.local. root.com6.local. 2014011404 180 90 360 180
com6.local.		180	IN	NS	ns.com6.local.
com6.local.		180	IN	MX	10 mail.com6.local.

;; Query time: 0 msec
;; SERVER: 10.1.6.1#53(10.1.6.1) (TCP)
;; WHEN: Fri Apr 24 09:55:20 JST 2026
;; MSG SIZE  rcvd: 162

[manage@bravo ~]$ exit
exit
> 
> ssh manage@10.1.6.2
manage@10.1.6.2's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Fri Apr 24 09:51:42 2026 from 10.1.6.1
[manage@victor ~]$ uname -a
Linux victor.com6.local 4.18.0-553.el8_10.x86_64 #1 SMP Fri May 24 13:05:10 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
[manage@victor ~]$ uname -a
Linux victor.com6.local 4.18.0-553.el8_10.x86_64 #1 SMP Fri May 24 13:05:10 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
[manage@victor ~]$ hostname
victor.com6.local
[manage@victor ~]$ ifconfig | grep -E 'inet |ether'
        inet 10.1.6.2  netmask 255.255.255.0  broadcast 10.1.6.255
        ether bc:24:11:a3:8a:70  txqueuelen 1000  (Ethernet)
        inet 127.0.0.1  netmask 255.0.0.0
[manage@victor ~]$ sockstat -4 -l | head -40
-bash: sockstat: コマンドが見つかりません
[manage@victor ~]$ service -e
The service command supports only basic LSB actions (start, stop, restart, try-restart, reload, force-reload, status). For other actions, please try to use systemctl.
[manage@victor ~]$ ls /usr/local/etc/ | head
[manage@victor ~]$ ls /var/db/mysql/ 2>/dev/null | head
[manage@victor ~]$ ls /usr/local/www/ 2>/dev/null
[manage@victor ~]$ cat /etc/os-release
NAME="Rocky Linux"
VERSION="8.10 (Green Obsidian)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="8.10"
PLATFORM_ID="platform:el8"
PRETTY_NAME="Rocky Linux 8.10 (Green Obsidian)"
ANSI_COLOR="0;32"
LOGO="fedora-logo-icon"
CPE_NAME="cpe:/o:rocky:rocky:8:GA"
HOME_URL="https://rockylinux.org/"
BUG_REPORT_URL="https://bugs.rockylinux.org/"
SUPPORT_END="2029-05-31"
ROCKY_SUPPORT_PRODUCT="Rocky-Linux-8"
ROCKY_SUPPORT_PRODUCT_VERSION="8.10"
REDHAT_SUPPORT_PRODUCT="Rocky Linux"
REDHAT_SUPPORT_PRODUCT_VERSION="8.10"
[manage@victor ~]$ cat /etc/redhat-release 2>/dev/null
Rocky Linux release 8.10 (Green Obsidian)
[manage@victor ~]$ ss -tlnp
State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port  Process  
LISTEN   0        10               0.0.0.0:25            0.0.0.0:*              
LISTEN   0        100              0.0.0.0:993           0.0.0.0:*              
LISTEN   0        25               0.0.0.0:514           0.0.0.0:*              
LISTEN   0        128            127.0.0.1:199           0.0.0.0:*              
LISTEN   0        100              0.0.0.0:143           0.0.0.0:*              
LISTEN   0        128              0.0.0.0:22            0.0.0.0:*              
LISTEN   0        128                    *:23                  *:*              
LISTEN   0        100                 [::]:993              [::]:*              
LISTEN   0        25                  [::]:514              [::]:*              
LISTEN   0        80                     *:3306                *:*              
LISTEN   0        100                 [::]:143              [::]:*              
LISTEN   0        128                    *:80                  *:*              
LISTEN   0        128                 [::]:22               [::]:*              
[manage@victor ~]$ ss -ulnp
State   Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process  
UNCONN  0        0                0.0.0.0:34020          0.0.0.0:*              
UNCONN  0        0                0.0.0.0:67             0.0.0.0:*              
UNCONN  0        0                0.0.0.0:161            0.0.0.0:*              
UNCONN  0        0              127.0.0.1:323            0.0.0.0:*              
UNCONN  0        0                0.0.0.0:514            0.0.0.0:*              
UNCONN  0        0                   [::]:45332             [::]:*              
UNCONN  0        0                  [::1]:323               [::]:*              
UNCONN  0        0                   [::]:514               [::]:*              
[manage@victor ~]$ systemctl list-units --type=service --state=running
UNIT                     LOAD   ACTIVE SUB     DESCRIPTION                     
atd.service              loaded active running Job spooling tools              
auditd.service           loaded active running Security Auditing Service       
chronyd.service          loaded active running NTP client/server               
crond.service            loaded active running Command Scheduler               
dbus.service             loaded active running D-Bus System Message Bus        
dhcpd.service            loaded active running DHCPv4 Server Daemon            
dovecot.service          loaded active running Dovecot IMAP/POP3 email server  
getty@tty1.service       loaded active running Getty on tty1                   
httpd.service            loaded active running The Apache HTTP Server          
irqbalance.service       loaded active running irqbalance daemon               
libstoragemgmt.service   loaded active running libstoragemgmt plug-in server da>
mariadb.service          loaded active running MariaDB 10.3 database server    
mcelog.service           loaded active running Machine Check Exception Logging >
NetworkManager.service   loaded active running Network Manager                 
php-fpm.service          loaded active running The PHP FastCGI Process Manager 
polkit.service           loaded active running Authorization Manager           
rsyslog.service          loaded active running System Logging Service          
saslauthd.service        loaded active running SASL authentication daemon.     
sendmail.service         loaded active running Sendmail Mail Transport Agent   
sm-client.service        loaded active running Sendmail Mail Transport Client  
smartd.service           loaded active running Self Monitoring and Reporting Te>
snmpd.service            loaded active running Simple Network Management Protoc>
sshd.service             loaded active running OpenSSH server daemon           

[manage@victor ~]$ ps auxf | head -50
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           2  0.0  0.0      0     0 ?        S    00:32   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [rcu_par_gp]
root           5  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [slub_flushwq]
root           7  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [kworker/0:0H-events_highpri]
root           8  0.0  0.0      0     0 ?        I    00:32   0:00  \_ [kworker/u4:0-events_unbound]
root           9  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [mm_percpu_wq]
root          10  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [rcu_tasks_rude_]
root          11  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [rcu_tasks_trace]
root          12  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [ksoftirqd/0]
root          13  0.0  0.0      0     0 ?        I    00:32   0:00  \_ [rcu_sched]
root          14  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [migration/0]
root          15  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [watchdog/0]
root          16  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [cpuhp/0]
root          17  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [cpuhp/1]
root          18  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [watchdog/1]
root          19  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [migration/1]
root          20  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [ksoftirqd/1]
root          22  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [kworker/1:0H-events_highpri]
root          24  0.0  0.0      0     0 ?        I    00:32   0:00  \_ [kworker/u4:1-events_unbound]
root          25  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [kdevtmpfs]
root          26  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [netns]
root          27  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [kauditd]
root          29  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [khungtaskd]
root          30  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [oom_reaper]
root          31  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [writeback]
root          32  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [kcompactd0]
root          33  0.0  0.0      0     0 ?        SN   00:32   0:00  \_ [ksmd]
root          34  0.0  0.0      0     0 ?        SN   00:32   0:00  \_ [khugepaged]
root          35  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [crypto]
root          36  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [kintegrityd]
root          37  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [kblockd]
root          38  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [blkcg_punt_bio]
root          39  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [tpm_dev_wq]
root          40  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [md]
root          41  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [md_bitmap]
root          42  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [edac-poller]
root          43  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [watchdogd]
root          45  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [kworker/0:1H-kblockd]
root          52  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [kswapd0]
root         112  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [kthrotld]
root         114  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [acpi_thermal_pm]
root         115  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [kmpath_rdacd]
root         116  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [kaluad]
root         117  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [ipv6_addrconf]
root         118  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [kstrp]
root         157  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [zswap-shrink]
root         171  0.0  0.0      0     0 ?        I<   00:32   0:00  \_ [kworker/1:1H-xfs-log/dm-0]
root         376  0.0  0.0      0     0 ?        S    00:32   0:00  \_ [scsi_eh_0]
[manage@victor ~]$ sudo firewall-cmd --list-all 2>/dev/null
[sudo] manage のパスワード:
[manage@victor ~]$ sudo iptables -L -n 2>/dev/null | head -40
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
[manage@victor ~]$ ls /var/log/ | head -30
anaconda
audit
btmp
btmp-20260424
chrony
cron
dhcp.log
dnf.librepo.log
dnf.log
dnf.rpm.log
firewalld
hawkey.log
hawkey.log-20260424
httpd
kdump.log
lastlog
mail
maillog
mariadb
messages
php-fpm
private
rsyslog
samba
secure
spooler
squid
sssd
tuned
wtmp
[manage@victor ~]$ ls /etc/httpd/ 2>/dev/null
conf  conf.d  conf.modules.d  logs  modules  run  state
[manage@victor ~]$ ls /etc/nginx/ 2>/dev/null
conf.d  default.d
[manage@victor ~]$ ls /var/www/ 2>/dev/null
backup_html  cgi-bin  html  mrtg  rain  wordpress
[manage@victor ~]$ ls /var/lib/mysql/ 2>/dev/null
aria_log.00000001  ib_logfile0  multi-master.info   performance_schema
aria_log_control   ib_logfile1  mysql               rainloop
bbs_db             ibdata1      mysql.sock          tc.log
ib_buffer_pool     ibtmp1       mysql_upgrade_info  wordpress
[manage@victor ~]$ ls /var/lib/pgsql/ 2>/dev/null
[manage@victor ~]$ ls /etc/postfix/ 2>/dev/null
[manage@victor ~]$ ls /etc/dovecot/ 2>/dev/null
conf.d  dovecot.conf
[manage@victor ~]$ dig @10.1.6.1 ns.com6.local

; <<>> DiG 9.11.36-RedHat-9.11.36-16.el8_10.6 <<>> @10.1.6.1 ns.com6.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4848
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 5e42ab9991e71e260100000069eac0c2a7285dc74587297f (good)
;; QUESTION SECTION:
;ns.com6.local.			IN	A

;; ANSWER SECTION:
ns.com6.local.		180	IN	A	10.1.6.1

;; Query time: 0 msec
;; SERVER: 10.1.6.1#53(10.1.6.1)
;; WHEN: 金  4月 24 10:00:50 JST 2026
;; MSG SIZE  rcvd: 86

[manage@victor ~]$ dig @10.1.6.1 mail.com6.local

; <<>> DiG 9.11.36-RedHat-9.11.36-16.el8_10.6 <<>> @10.1.6.1 mail.com6.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 50234
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 580e26d34a96b9520100000069eac0c58b0a73914822bf81 (good)
;; QUESTION SECTION:
;mail.com6.local.		IN	A

;; ANSWER SECTION:
mail.com6.local.	180	IN	A	10.1.6.2

;; Query time: 0 msec
;; SERVER: 10.1.6.1#53(10.1.6.1)
;; WHEN: 金  4月 24 10:00:53 JST 2026
;; MSG SIZE  rcvd: 88

[manage@victor ~]$ dig @10.1.6.1 www.com6.local

; <<>> DiG 9.11.36-RedHat-9.11.36-16.el8_10.6 <<>> @10.1.6.1 www.com6.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53782
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 71c4f4ab1504a67f0100000069eac0c93d9261458755d8b2 (good)
;; QUESTION SECTION:
;www.com6.local.			IN	A

;; ANSWER SECTION:
www.com6.local.		180	IN	A	10.1.6.2

;; Query time: 0 msec
;; SERVER: 10.1.6.1#53(10.1.6.1)
;; WHEN: 金  4月 24 10:00:57 JST 2026
;; MSG SIZE  rcvd: 87

[manage@victor ~]$ dig @10.1.6.1 www.com6.local

; <<>> DiG 9.11.36-RedHat-9.11.36-16.el8_10.6 <<>> @10.1.6.1 www.com6.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51322
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: f892854f966f31dd0100000069eac0cbe3490f740e7b6866 (good)
;; QUESTION SECTION:
;www.com6.local.			IN	A

;; ANSWER SECTION:
www.com6.local.		180	IN	A	10.1.6.2

;; Query time: 0 msec
;; SERVER: 10.1.6.1#53(10.1.6.1)
;; WHEN: 金  4月 24 10:00:59 JST 2026
;; MSG SIZE  rcvd: 87

[manage@victor ~]$ dig @10.1.6.1 service.com6.local ANY

; <<>> DiG 9.11.36-RedHat-9.11.36-16.el8_10.6 <<>> @10.1.6.1 service.com6.local ANY
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 31692
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 319b0af5a9e1cb820100000069eac0cfccf3ca9b0644075d (good)
;; QUESTION SECTION:
;service.com6.local.		IN	ANY

;; ANSWER SECTION:
service.com6.local.	180	IN	SOA	ns.com6.local. root.com6.local. 2014011404 180 90 360 180
service.com6.local.	180	IN	NS	ns.com6.local.
service.com6.local.	180	IN	MX	10 bravo.com6.local.
service.com6.local.	180	IN	A	10.1.6.1

;; Query time: 0 msec
;; SERVER: 10.1.6.1#53(10.1.6.1)
;; WHEN: 金  4月 24 10:01:03 JST 2026
;; MSG SIZE  rcvd: 171

[manage@victor ~]$ dig @10.1.6.1 com6.local AXFR

; <<>> DiG 9.11.36-RedHat-9.11.36-16.el8_10.6 <<>> @10.1.6.1 com6.local AXFR
; (1 server found)
;; global options: +cmd
; Transfer failed.
[manage@victor ~]$ Read from remote host 10.1.6.1: Operation timed out
Connection to 10.1.6.1 closed.
client_loop: send disconnect: Broken pipe
ryu@Mac ~ %ssh manage@10.1.6.1

^C
ryu@Mac ~ %ssh manage@10.1.6.1

(manage@10.1.6.1) Password for manage@bravo.com6.local:
Last login: Fri Apr 24 10:37:03 2026 from 10.1.16.16
FreeBSD 14.3-RELEASE (GENERIC) releng/14.3-n271432-8c9ce319fef7

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List:        https://www.FreeBSD.org/lists/questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

To change this login announcement, see motd(5).
> bash
[manage@bravo ~]$ httpd -v
Server version: Apache/2.4.66 (FreeBSD)
Server built:   unknown
[manage@bravo ~]$ php -v
PHP Warning:  PHP Startup: Unable to load dynamic library 'php_mysqli.dll' (tried: /usr/local/lib/php/20250925/php_mysqli.dll (Cannot open "/usr/local/lib/php/20250925/php_mysqli.dll"), /usr/local/lib/php/20250925/php_mysqli.dll.so (Cannot open "/usr/local/lib/php/20250925/php_mysqli.dll.so")) in Unknown on line 0
PHP 8.5.1 (cli) (built: Mar  5 2026 01:05:45) (NTS)
Copyright (c) The PHP Group
Zend Engine v4.5.1, Copyright (c) Zend Technologies
    with Zend OPcache v8.5.1, Copyright (c), by Zend Technologies
[manage@bravo ~]$ mysql -V
mysql  Ver 8.0.44 for FreeBSD14.3 on amd64 (Source distribution)
[manage@bravo ~]$ cat /var/www/wordpress/wp-includes/version.php 2>/dev/null
[manage@bravo ~]$ ls /var/www/rain/
ls: /var/www/rain/: そのようなファイルまたはディレクトリはありません
[manage@bravo ~]$ ls /var/www/html/ | head -30
ls: /var/www/html/: そのようなファイルまたはディレクトリはありません
[manage@bravo ~]$ ls /etc/httpd/conf.d/
ls: /etc/httpd/conf.d/: そのようなファイルまたはディレクトリはありません
[manage@bravo ~]$ sudo cat /etc/httpd/conf.d/*.conf | head -100
パスワード: 
sudo: パスワードが必要です

[manage@bravo ~]$ exit 
exit
> ssh manage@10.1.6.2
manage@10.1.6.2's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Fri Apr 24 10:37:25 2026 from 10.1.16.16
[manage@victor ~]$ httpd -v
Server version: Apache/2.4.37 (Rocky Linux)
Server built:   Dec 22 2025 07:39:40
[manage@victor ~]$ php -v
PHP 7.2.24 (cli) (built: Oct 22 2019 08:28:36) ( NTS )
Copyright (c) 1997-2018 The PHP Group
Zend Engine v3.2.0, Copyright (c) 1998-2018 Zend Technologies
[manage@victor ~]$ mysql -V
mysql  Ver 15.1 Distrib 10.3.39-MariaDB, for Linux (x86_64) using readline 5.1
[manage@victor ~]$ cat /var/www/wordpress/wp-includes/version.php 2>/dev/null | grep wp_version
 * @global string $wp_version
$wp_version = '4.9.4';
[manage@victor ~]$ ls /var/www/rain/
data  index.php  rainloop
[manage@victor ~]$ ls /var/www/html/ | head -30
[manage@victor ~]$ ls /etc/httpd/conf.d/
README          mrtg.conf  squid.conf    welcome.conf
autoindex.conf  php.conf   userdir.conf
[manage@victor ~]$ sudo cat /etc/httpd/conf/httpd.conf | grep -iE 'ServerName|DocumentRoot|Listen|Include' | head -30
[sudo] manage のパスワード:
# Listen: Allows you to bind Apache to specific IP addresses and/or
# Change this to Listen on specific IP addresses as shown below to 
#Listen 12.34.56.78:80
Listen 80
Include conf.modules.d/*.conf
# ServerName gives the name and port that the server uses to identify itself.
#ServerName www.example.com:80
# DocumentRoot: The directory out of which you will serve your
DocumentRoot "/var/www/wordpress"
    #   Indexes Includes FollowSymLinks SymLinksifOwnerMatch ExecCGI MultiViews
    Options Includes ExecCGI FollowSymLinks
# Possible values include: debug, info, notice, warn, error, crit,
    # access content that does not live under the DocumentRoot.
    # If you include a trailing / on /webpath then the server will
    # To parse .shtml files for server-side includes (SSI):
    # (You will also need to add "Includes" to the "Options" directive.)
    AddOutputFilter INCLUDES .shtml
IncludeOptional conf.d/*.conf
[manage@victor ~]$ sudo cat /etc/httpd/conf.d/*.conf 2>/dev/null | head -100
#
# Directives controlling the display of server-generated directory listings.
#
# Required modules: mod_authz_core, mod_authz_host,
#                   mod_autoindex, mod_alias
#
# To see the listing of a directory, the Options directive for the
# directory must include "Indexes", and the directory must not contain
# a file matching those listed in the DirectoryIndex directive.
#

#
# IndexOptions: Controls the appearance of server-generated directory
# listings.
#
IndexOptions FancyIndexing HTMLTable VersionSort

# We include the /icons/ alias for FancyIndexed directory listings.  If
# you do not use FancyIndexing, you may comment this out.
#
Alias /icons/ "/usr/share/httpd/icons/"

<Directory "/usr/share/httpd/icons">
    Options MultiViews
    AllowOverride None
    Require all granted
</Directory>

#
# AddIcon* directives tell the server which icon to show for different
# files or filename extensions.  These are only displayed for
# FancyIndexed directories.
#
AddIconByEncoding (CMP,/icons/compressed.gif) x-compress x-gzip

AddIconByType (TXT,/icons/text.gif) text/*
AddIconByType (IMG,/icons/image2.gif) image/*
AddIconByType (SND,/icons/sound2.gif) audio/*
AddIconByType (VID,/icons/movie.gif) video/*

AddIcon /icons/binary.gif .bin .exe
AddIcon /icons/binhex.gif .hqx
AddIcon /icons/tar.gif .tar
AddIcon /icons/world2.gif .wrl .wrl.gz .vrml .vrm .iv
AddIcon /icons/compressed.gif .Z .z .tgz .gz .zip
AddIcon /icons/a.gif .ps .ai .eps
AddIcon /icons/layout.gif .html .shtml .htm .pdf
AddIcon /icons/text.gif .txt
AddIcon /icons/c.gif .c
AddIcon /icons/p.gif .pl .py
AddIcon /icons/f.gif .for
AddIcon /icons/dvi.gif .dvi
AddIcon /icons/uuencoded.gif .uu
AddIcon /icons/script.gif .conf .sh .shar .csh .ksh .tcl
AddIcon /icons/tex.gif .tex
AddIcon /icons/bomb.gif /core
AddIcon /icons/bomb.gif */core.*

AddIcon /icons/back.gif ..
AddIcon /icons/hand.right.gif README
AddIcon /icons/folder.gif ^^DIRECTORY^^
AddIcon /icons/blank.gif ^^BLANKICON^^

#
# DefaultIcon is which icon to show for files which do not have an icon
# explicitly set.
#
DefaultIcon /icons/unknown.gif

#
# AddDescription allows you to place a short description after a file in
# server-generated indexes.  These are only displayed for FancyIndexed
# directories.
# Format: AddDescription "description" filename
#
#AddDescription "GZIP compressed document" .gz
#AddDescription "tar archive" .tar
#AddDescription "GZIP compressed tar archive" .tgz

#
# ReadmeName is the name of the README file the server will look for by
# default, and append to directory listings.
#
# HeaderName is the name of a file which should be prepended to
# directory indexes. 
ReadmeName README.html
HeaderName HEADER.html

#
# IndexIgnore is a set of filenames which directory indexing should ignore
# and not include in the listing.  Shell-style wildcarding is permitted.
#
IndexIgnore .??* *~ *# HEADER* README* RCS CVS *,v *,t

Alias /mrtg /var/www/mrtg
#
# The following lines prevent .user.ini files from being viewed by Web clients.
#
<Files ".user.ini">
    Require all denied
[manage@victor ~]$ sudo systemctl status firewalld --no-pager | head -5
● firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; disabled; vendor preset: enabled)
   Active: inactive (dead)
     Docs: man:firewalld(1)
[manage@victor ~]$ getenforce
Disabled
[manage@victor ~]$ sudo cat /etc/dhcp/dhcpd.conf 2>/dev/null | head -60
#
# DHCP Server Configuration file.
#   see /usr/share/doc/dhcp-server/dhcpd.conf.example
#   see dhcpd.conf(5) man page
#
option domain-name "com6.local";
option domain-name-servers 10.1.6.1;

ddns-update-style interim;

ignore client-updates;
not authoritative;
log-facility local3;
subnet 10.1.16.0 netmask 255.255.255.0 {
	option broadcast-address 10.1.16.255;
	option routers                  10.1.16.254;
	option subnet-mask              255.255.255.0;
	range dynamic-bootp             10.1.16.50 10.1.16.99;
}

zone com6.local {
	primary 10.1.6.1;
}

zone 16.1.10.in-add.arpa{
	primary 10.1.6.1;
}

subnet 10.1.6.0 netmask 255.255.255.0{
}

[manage@victor ~]$ sudo grep -iE '^rocommunity|^rwcommunity|^community|^agentaddress' /etc/snmp/snmpd.conf 2>/dev/null
[manage@victor ~]$ echo "=== httpd.conf (clean) ==="
=== httpd.conf (clean) ===
[manage@victor ~]$ sudo grep -vE '^\s*#|^\s*$' /etc/httpd/conf/httpd.conf | head -80
[sudo] manage のパスワード:
残念、また試してください。
[sudo] manage のパスワード:
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin root@localhost
<Directory />
    Options FollowSymLinks ExecCGI
    AllowOverride All
</Directory>
DocumentRoot "/var/www/wordpress"
<Directory "/var/www">
    AllowOverride None
    Require all granted
</Directory>
<Directory "/var/www/html">
    Options Includes ExecCGI FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
<IfModule dir_module>
    DirectoryIndex index.php index.html
</IfModule>
<Files ".ht*">
    Require all denied
</Files>
ErrorLog "logs/error_log"
LogLevel warn
<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common
    <IfModule logio_module>
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O" combinedio
    </IfModule>
    CustomLog "logs/access_log" combined
</IfModule>
<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
</IfModule>
<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>
<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddHandler cgi-script .cgi .pi
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>
<IfModule mime_magic_module>
    MIMEMagicFile conf/magic
</IfModule>
EnableSendfile on
IncludeOptional conf.d/*.conf
ServerTokens Prod
Alias /rain /var/www/rain
<Directory /var/www/rain/data>
	Order allow,deny
	Deny from all
</Directory>
[manage@victor ~]$ head -30 /var/www/rain/index.php
<?php

if (!defined('APP_VERSION'))
{
	define('APP_VERSION', '1.12.0');
	define('APP_VERSION_TYPE', 'standard');
	define('APP_INDEX_ROOT_FILE', __FILE__);
	define('APP_INDEX_ROOT_PATH', str_replace('\\', '/', rtrim(dirname(__FILE__), '\\/').'/'));
}

if (file_exists(APP_INDEX_ROOT_PATH.'rainloop/v/'.APP_VERSION.'/include.php'))
{
	include APP_INDEX_ROOT_PATH.'rainloop/v/'.APP_VERSION.'/include.php';
}
else
{
	echo '[105] Missing version directory';
	exit(105);
}
[manage@victor ~]$ ls /var/www/rain/rainloop/ 2>/dev/null
v
[manage@victor ~]$ find /var/www/rain/rainloop -maxdepth 3 -name 'VERSION' 2>/dev/null
[manage@victor ~]$ cat /var/www/rain/rainloop/data/VERSION 2>/dev/null
[manage@victor ~]$ 
[manage@victor ~]$ cat /var/www/rain/rainloop/rainloop/v/*/VERSION 2>/dev/null 2>&1 | head
cat: '/var/www/rain/rainloop/rainloop/v/*/VERSION': No such file or directory
[manage@victor ~]$ ls /var/www/wordpress/wp-content/plugins/
akismet  hello.php  index.php  wp-multibyte-patch
[manage@victor ~]$ ls /var/www/wordpress/wp-content/themes/
index.php  twentyeleven  twentyfifteen  twentyseventeen  twentysixteen
[manage@victor ~]$ ls -la /var/www/wordpress/wp-config.php
-rw-r--r-- 1 apache apache 3868  4月 15 16:03 /var/www/wordpress/wp-config.php
[manage@victor ~]$ ls /var/www/backup_html/ | head -20
bbs
bbs_admin
business
careers
conf.cgi
history
img
index.html
log.dat
member
search.cgi
search.html
stock
[manage@victor ~]$ sudo ss -tlnp | grep ':23 '
LISTEN 0      128                *:23              *:*    users:(("systemd",pid=1,fd=45))                                                                                            
[manage@victor ~]$ sudo ss -ulnp | grep '34020'
UNCONN 0      0            0.0.0.0:34020      0.0.0.0:*    users:(("dhcpd",pid=927,fd=20))  
[manage@victor ~]$ systemctl list-units --type=socket --state=listening | head
UNIT                    LOAD   ACTIVE SUB       DESCRIPTION                                 
dm-event.socket         loaded active listening Device-mapper event daemon FIFOs            
lvm2-lvmpolld.socket    loaded active listening LVM2 poll daemon socket                     
sssd-kcm.socket         loaded active listening SSSD Kerberos Cache Manager responder socket
systemd-coredump.socket loaded active listening Process Core Dump Socket                    
systemd-initctl.socket  loaded active listening initctl Compatibility Named Pipe            
telnet.socket           loaded active listening Telnet Server Activation Socket             

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
[manage@victor ~]$ ls /etc/xinetd.d/ 2>/dev/null
[manage@victor ~]$ sudo grep -vE '^\s*#|^\s*$' /etc/snmp/snmpd.conf | head -40
com2sec notConfigUser  default       public
group   notConfigGroup v1           notConfigUser
group   notConfigGroup v2c           notConfigUser
view    systemview    included   .1.3.6.1.2.1.1
view    systemview    included   .1.3.6.1.2.1.25.1.1
access  notConfigGroup ""      any       noauth    exact  systemview none none
syslocation Unknown (edit /etc/snmp/snmpd.conf)
syscontact Root <root@localhost> (configure /etc/snmp/snmp.local.conf)
dontLogTCPWrappersConnects yes
[manage@victor ~]$ ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
/etc/cron.d/:
0hourly  mrtg  raid-check

/etc/cron.daily/:
logrotate

/etc/cron.hourly/:
0anacron
[manage@victor ~]$ sudo ls /var/spool/cron/ 2>/dev/null
[manage@victor ~]$ awk -F: '$7 ~ /bash|sh$/ {print $1,$3,$6,$7}' /etc/passwd | head -40
root 0 /root /bin/bash
aizawa 1001 /home/aizawa /bin/bash
akagi 1002 /home/akagi /bin/bash
arai 1003 /home/arai /bin/bash
amano 1004 /home/amano /bin/bash
amuro 1005 /home/amuro /bin/bash
ishikawa 1006 /home/ishikawa /bin/bash
ishibashi 1007 /home/ishibashi /bin/bash
itou 1008 /home/itou /bin/bash
ichihara 1009 /home/ichihara /bin/bash
imamura 1010 /home/imamura /bin/bash
irino 1011 /home/irino /bin/bash
ueda 1012 /home/ueda /bin/bash
utagawa 1013 /home/utagawa /bin/bash
umino 1014 /home/umino /bin/bash
etou 1015 /home/etou /bin/bash
egawa 1016 /home/egawa /bin/bash
okada 1017 /home/okada /bin/bash
ogawa 1018 /home/ogawa /bin/bash
ozeki 1019 /home/ozeki /bin/bash
oda 1020 /home/oda /bin/bash
onoda 1021 /home/onoda /bin/bash
kai 1022 /home/kai /bin/bash
kagawa 1023 /home/kagawa /bin/bash
katakura 1024 /home/katakura /bin/bash
kanemoto 1025 /home/kanemoto /bin/bash
kamei 1026 /home/kamei /bin/bash
karasawa 1027 /home/karasawa /bin/bash
kawamura 1028 /home/kawamura /bin/bash
kitajima 1029 /home/kitajima /bin/bash
kimino 1030 /home/kimino /bin/bash
kira 1031 /home/kira /bin/bash
kindaichi 1032 /home/kindaichi /bin/bash
kudou 1033 /home/kudou /bin/bash
kumazawa 1034 /home/kumazawa /bin/bash
kobayashi 1035 /home/kobayashi /bin/bash
komiyama 1036 /home/komiyama /bin/bash
sakai 1037 /home/sakai /bin/bash
sakaguchi 1038 /home/sakaguchi /bin/bash
sawamura 1039 /home/sawamura /bin/bash
[manage@victor ~]$ last -n 15
manage   pts/4        10.1.16.12       Fri Apr 24 10:47 - 10:47  (00:00)
manage   pts/3        10.1.6.1         Fri Apr 24 10:39   still logged in
manage   pts/3        10.1.16.16       Fri Apr 24 10:37 - 10:37  (00:00)
manage   pts/2        10.1.16.15       Fri Apr 24 10:33   still logged in
manage   pts/2        10.1.16.12       Fri Apr 24 10:31 - 10:32  (00:00)
manage   pts/1        10.1.6.1         Fri Apr 24 09:56   still logged in
manage   pts/1        10.1.6.1         Fri Apr 24 09:51 - 09:54  (00:03)
manage   pts/0        10.1.16.16       Fri Apr 24 08:37   still logged in
manage   pts/0        10.1.16.16       Fri Apr 24 08:32 - 08:33  (00:00)
manage   pts/1        10.1.129.10      Fri Apr 24 01:43 - 04:00  (02:16)
obuchi   pts/0        10.1.129.10      Fri Apr 24 01:40 - 04:00  (02:19)
reboot   system boot  4.18.0-553.el8_1 Fri Apr 24 00:32   still running
root     tty1                          Thu Apr 23 19:07 - 19:07  (00:00)
reboot   system boot  4.18.0-553.el8_1 Thu Apr 23 18:10 - 19:07  (00:56)

wtmp は Wed Apr 15 16:07:01 2026 から始まっています
[manage@victor ~]$ sudo find /var/www -type f -mtime -14 2>/dev/null | head -30
/var/www/cgi-bin/.my.cnf.6804
/var/www/cgi-bin/.mysql.6804
/var/www/rain/data/EMPTY
/var/www/rain/data/VERSION
/var/www/rain/data/SALT.php
/var/www/rain/data/INSTALLED
/var/www/rain/data/index.html
/var/www/rain/data/index.php
/var/www/rain/data/_data_/_default_/cache/47/91/47916b7ebf0d20007ea6d25a6ef9f42af2a65641
/var/www/rain/data/_data_/_default_/cache/2c/61/2c61bfdf22f78c5b8c1a793cf350f54a5ed54885
/var/www/rain/data/_data_/_default_/cache/e7/ce/e7ce5587bbda05a75c27ebe08e1309a93680d2c9
/var/www/rain/data/_data_/_default_/cache/6c/46/6c46d99e59ee099592e9be744ea70c17d70f662b
/var/www/rain/data/_data_/_default_/cache/81/ab/81abffd6440b99bdcca020e1b9c49466f5ada7e1
/var/www/rain/data/_data_/_default_/cache/0e/ea/0eead3b7915dbc1924dee134aa7ad5660722c11a
/var/www/rain/data/_data_/_default_/configs/application.ini
/var/www/rain/data/_data_/_default_/storage/cfg/ma/manage@com1.local/sign_me
/var/www/rain/data/_data_/_default_/storage/cfg/ma/manage@com1.local/settings_local
/var/www/rain/data/_data_/_default_/storage/cfg/ma/manage@com6.local/settings_local
/var/www/rain/data/_data_/_default_/storage/cfg/ak/akagi@com1.local/settings_local
/var/www/rain/data/_data_/_default_/storage/cfg/is/ishikawa@com1.local/settings_local
/var/www/rain/data/_data_/_default_/storage/cfg/ka/katsura@service.com1.local/settings_local
/var/www/rain/data/_data_/_default_/storage/data/__nobody__/ef/efaeb36a60ef9682802c6a704c2d784d
/var/www/rain/data/_data_/_default_/domains/disabled
/var/www/rain/data/_data_/_default_/domains/gmail.com.ini
/var/www/rain/data/_data_/_default_/domains/outlook.com.ini
/var/www/rain/data/_data_/_default_/domains/qq.com.ini
/var/www/rain/data/_data_/_default_/domains/yahoo.com.ini
/var/www/rain/data/_data_/_default_/domains/com6.local.ini
/var/www/rain/data/_data_/_default_/domains/service.com6.local.ini
/var/www/rain/index.php
[manage@victor ~]$ sudo find / -xdev -perm -4000 -type f 2>/dev/null | head -30
/usr/bin/su
/usr/bin/umount
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/crontab
/usr/bin/sudo
/usr/bin/at
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/chsh
/usr/sbin/unix_chkpwd
/usr/sbin/grub2-set-bootflag
/usr/sbin/pam_timestamp_check
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/sssd/krb5_child
/usr/libexec/sssd/ldap_child
/usr/libexec/sssd/selinux_child
/usr/libexec/sssd/proxy_child
/usr/libexec/cockpit-session
[manage@victor ~]$ sudo ss -antp state established 2>/dev/null | head -20
Recv-Q Send-Q Local Address:Port Peer Address:Port Process                                               
0      0           10.1.6.2:22     10.1.16.15:63718 users:(("sshd",pid=3739,fd=4),("sshd",pid=3736,fd=4))
0      92          10.1.6.2:22       10.1.6.1:55067 users:(("sshd",pid=3901,fd=4),("sshd",pid=3899,fd=4))
0      0           10.1.6.2:22     10.1.16.16:50318 users:(("sshd",pid=2900,fd=4),("sshd",pid=2888,fd=4))
0      0           10.1.6.2:22     10.1.16.12:59996 users:(("sshd",pid=4250,fd=4),("sshd",pid=4249,fd=4))
0      0           10.1.6.2:22       10.1.6.1:14391 users:(("sshd",pid=3479,fd=4),("sshd",pid=3477,fd=4))
[manage@victor ~]$ sudo find / -maxdepth 3 -type d 2>/dev/null > /tmp/victor_tree_d3.txt
[sudo] manage のパスワード:
[manage@victor ~]$ wc -l /tmp/victor_tree_d3.txt && head -40 /tmp/victor_tree_d3.txt
2355 /tmp/victor_tree_d3.txt
/
/boot
/boot/efi
/boot/efi/EFI
/boot/grub2
/boot/grub2/i386-pc
/boot/grub2/fonts
/boot/loader
/boot/loader/entries
/dev
/dev/dri
/dev/dri/by-path
/dev/snd
/dev/vfio
/dev/net
/dev/hugepages
/dev/mqueue
/dev/rl
/dev/disk
/dev/disk/by-label
/dev/disk/by-uuid
/dev/disk/by-partuuid
/dev/disk/by-path
/dev/disk/by-id
/dev/block
/dev/bsg
/dev/char
/dev/mapper
/dev/pts
/dev/shm
/dev/input
/dev/input/by-id
/dev/input/by-path
/dev/bus
/dev/bus/usb
/dev/raw
/dev/cpu
/dev/cpu/1
/dev/cpu/0
/proc
[manage@victor ~]$ sudo find /etc -type f 2>/dev/null > /tmp/victor_etc_files.txt
[manage@victor ~]$ wc -l /tmp/victor_etc_files.txt
614 /tmp/victor_etc_files.txt
[manage@victor ~]$ sudo find /var/www -maxdepth 5 2>/dev/null > /tmp/victor_www_tree.txt
[manage@victor ~]$ wc -l /tmp/victor_www_tree.txt
1618 /tmp/victor_www_tree.txt
[manage@victor ~]$ head -80 /tmp/victor_www_tree.txt
/var/www
/var/www/cgi-bin
/var/www/cgi-bin/.my.cnf.6804
/var/www/cgi-bin/.mysql.6804
/var/www/rain
/var/www/rain/data
/var/www/rain/data/EMPTY
/var/www/rain/data/VERSION
/var/www/rain/data/SALT.php
/var/www/rain/data/INSTALLED
/var/www/rain/data/index.html
/var/www/rain/data/index.php
/var/www/rain/data/_data_
/var/www/rain/data/_data_/_default_
/var/www/rain/data/_data_/_default_/logs
/var/www/rain/data/_data_/_default_/cache
/var/www/rain/data/_data_/_default_/configs
/var/www/rain/data/_data_/_default_/plugins
/var/www/rain/data/_data_/_default_/storage
/var/www/rain/data/_data_/_default_/domains
/var/www/rain/index.php
/var/www/rain/rainloop
/var/www/rain/rainloop/v
/var/www/rain/rainloop/v/1.12.0
/var/www/rain/rainloop/v/1.12.0/app
/var/www/rain/rainloop/v/1.12.0/check.php
/var/www/rain/rainloop/v/1.12.0/include.php
/var/www/rain/rainloop/v/1.12.0/index.php
/var/www/rain/rainloop/v/1.12.0/index.php.root
/var/www/rain/rainloop/v/1.12.0/static
/var/www/rain/rainloop/v/1.12.0/themes
/var/www/html
/var/www/backup_html
/var/www/backup_html/careers
/var/www/backup_html/careers/careers.bak
/var/www/backup_html/careers/careers.html
/var/www/backup_html/careers/_careers.html.swp
/var/www/backup_html/conf.cgi
/var/www/backup_html/index.html
/var/www/backup_html/log.dat
/var/www/backup_html/search.cgi
/var/www/backup_html/search.html
/var/www/backup_html/history
/var/www/backup_html/history/history.bak
/var/www/backup_html/history/history.html
/var/www/backup_html/stock
/var/www/backup_html/stock/100506.pdf
/var/www/backup_html/stock/100506_2.pdf
/var/www/backup_html/stock/100510.pdf
/var/www/backup_html/stock/100519.pdf
/var/www/backup_html/stock/stock.html
/var/www/backup_html/bbs
/var/www/backup_html/bbs/read.php
/var/www/backup_html/bbs/test.php
/var/www/backup_html/bbs/postform.php
/var/www/backup_html/bbs/menu.php
/var/www/backup_html/bbs/post.php
/var/www/backup_html/bbs/login.php
/var/www/backup_html/bbs/logout.php
/var/www/backup_html/bbs/common.inc.php
/var/www/backup_html/bbs/delete_a.php
/var/www/backup_html/bbs_admin
/var/www/backup_html/bbs_admin/delete.php
/var/www/backup_html/bbs_admin/delete_a.php
/var/www/backup_html/bbs_admin/index.html
/var/www/backup_html/bbs_admin/register.php
/var/www/backup_html/bbs_admin/search.php
/var/www/backup_html/bbs_admin/update.php
/var/www/backup_html/bbs_admin/view.php
/var/www/backup_html/img
/var/www/backup_html/img/s_no_image2.jpg
/var/www/backup_html/img/s_no_image3.jpg
/var/www/backup_html/img/s_no_image4.jpg
/var/www/backup_html/img/s_no_image5.jpg
/var/www/backup_html/img/unsou.jpg
/var/www/backup_html/img/unsou_logo.jpg
/var/www/backup_html/img/stack_chart.jpg
/var/www/backup_html/img/stock_chart.jpg
/var/www/backup_html/img/s_no_image1.jpg
/var/www/backup_html/img/solution_logo.jpg
[manage@victor ~]$ sudo ls -laSh /var/log/ | head -40
合計 356K
-rw-rw-r--.  1 root   utmp   315K  4月 24 11:03 lastlog
-rw-r--r--   1 root   root   195K  4月 24 11:03 messages
-rw-r--r--   1 root   root    29K  4月 24 11:10 cron
-rw-r--r--.  1 root   root    18K  4月 24 10:11 dnf.log
-rw-r--r--   1 root   root    17K  4月 24 11:10 secure
-rw-r--r--   1 root   root    17K  4月 24 00:32 maillog
-rw-rw-r--.  1 root   utmp    16K  4月 24 11:03 wtmp
-rw-r--r--.  1 root   root   8.9K  4月 24 10:11 dnf.librepo.log
drwxr-xr-x. 15 root   root   4.0K  4月 24 03:51 .
drwxr-xr-x. 22 root   root   4.0K  4月 23 18:10 ..
drwxr-xr-x.  2 root   root   4.0K  4月 15 16:03 anaconda
-rw-r--r--   1 root   root   1.5K  4月 24 00:32 dhcp.log
-rw-------.  1 root   root   1.3K  4月 24 00:32 kdump.log
-rw-r--r--.  1 root   root    464  4月 24 10:11 dnf.rpm.log
-rw-r--r--   1 root   root    120  4月 24 10:11 hawkey.log
-rw-r--r--.  1 root   root    120  4月 24 01:35 hawkey.log-20260424
drwxr-xr-x   2 root   root     72  4月 15 16:03 rsyslog
drwxr-xr-x   2 apache root     44  4月 15 16:03 php-fpm
drwxr-xr-x   2 root   root     41  4月 15 16:03 httpd
drwxr-xr-x.  2 sssd   sssd     26  4月 15 16:03 sssd
drwxr-xr-x   2 mysql  mysql    25  4月 15 16:03 mariadb
drwxr-xr-x   2 root   root     24  4月 15 16:03 mail
drwx------.  2 root   root     23  4月 15 16:03 audit
drwxr-xr-x.  2 root   root     23  4月 15 16:03 tuned
drwxr-xr-x.  3 root   root     17  4月 15 16:03 samba
drwxr-xr-x.  2 chrony chrony    6  4月 15 16:03 chrony
drwx------.  2 root   root      6  4月 15 16:03 private
drwxr-xr-x   2 squid  root      6  4月 15 16:03 squid
-rw-rw----   1 root   utmp      0  4月 24 03:51 btmp
-rw-rw----.  1 root   utmp      0  4月 15 16:03 btmp-20260424
-rw-r--r--.  1 root   root      0  4月 15 16:03 firewalld
-rw-r--r--   1 root   root      0  4月 15 16:03 spooler
[manage@victor ~]$ sudo ls -la /home/
合計 8
drwxr-xr-x. 103 root      root      4096  4月 15 16:05 .
dr-xr-xr-x.  17 root      root       260  4月 15 16:03 ..
drwxr-xr-x    3 aizawa    aizawa      77  4月 15 16:03 aizawa
drwxr-xr-x    3 akagi     akagi       77  4月 15 16:03 akagi
drwxr-xr-x    3 amano     amano       77  4月 15 16:03 amano
drwxr-xr-x    3 amuro     amuro       77  4月 15 16:03 amuro
drwxr-xr-x    3 arai      arai        77  4月 15 16:03 arai
drwxr-xr-x    3 chida     chida       77  4月 15 16:03 chida
drwxr-xr-x    3 egawa     egawa       77  4月 15 16:03 egawa
drwxr-xr-x    3 etou      etou        77  4月 15 16:03 etou
drwxr-xr-x    3 hamada    hamada      77  4月 15 16:03 hamada
drwxr-xr-x    3 hara      hara        77  4月 15 16:03 hara
drwxr-xr-x    3 henmi     henmi       77  4月 15 16:03 henmi
drwxr-xr-x    3 higuchi   higuchi     77  4月 15 16:03 higuchi
drwxr-xr-x    3 hirota    hirota      77  4月 15 16:03 hirota
drwxr-xr-x    3 horikawa  horikawa    77  4月 15 16:03 horikawa
drwxr-xr-x    3 hoshino   hoshino     77  4月 15 16:03 hoshino
drwxr-xr-x    3 hosomi    hosomi      77  4月 15 16:03 hosomi
drwxr-xr-x    3 hukui     hukui       77  4月 15 16:03 hukui
drwxr-xr-x    3 huruta    huruta      77  4月 15 16:03 huruta
drwxr-xr-x    3 ichihara  ichihara    77  4月 15 16:03 ichihara
drwxr-xr-x    3 imamura   imamura     77  4月 15 16:03 imamura
drwxr-xr-x    3 irino     irino       77  4月 15 16:03 irino
drwxr-xr-x    3 ishibashi ishibashi   77  4月 15 16:03 ishibashi
drwxr-xr-x    3 ishikawa  ishikawa    77  4月 15 16:03 ishikawa
drwxr-xr-x    3 itou      itou        77  4月 15 16:03 itou
drwxr-xr-x    3 kagawa    kagawa      77  4月 15 16:03 kagawa
drwxr-xr-x    3 kai       kai         77  4月 15 16:03 kai
drwxr-xr-x    3 kamei     kamei       77  4月 15 16:03 kamei
drwxr-xr-x    3 kanemoto  kanemoto    77  4月 15 16:03 kanemoto
drwxr-xr-x    3 karasawa  karasawa    77  4月 15 16:03 karasawa
drwxr-xr-x    3 katakura  katakura    77  4月 15 16:03 katakura
drwxr-xr-x    3 kawamura  kawamura    77  4月 15 16:03 kawamura
drwxr-xr-x    3 kimino    kimino      77  4月 15 16:03 kimino
drwxr-xr-x    3 kindaichi kindaichi   77  4月 15 16:03 kindaichi
drwxr-xr-x    3 kira      kira        77  4月 15 16:03 kira
drwxr-xr-x    3 kitajima  kitajima    77  4月 15 16:03 kitajima
drwxr-xr-x    3 kobayashi kobayashi   77  4月 15 16:03 kobayashi
drwxr-xr-x    3 komiyama  komiyama    77  4月 15 16:03 komiyama
drwxr-xr-x    3 kudou     kudou       77  4月 15 16:03 kudou
drwxr-xr-x    3 kumazawa  kumazawa    77  4月 15 16:03 kumazawa
drwxr-xr-x    3 makita    makita      77  4月 15 16:03 makita
drwxr-xr-x    3 manage    manage    4096  4月 24 09:58 manage
drwxr-xr-x    3 maruyama  maruyama    77  4月 15 16:03 maruyama
drwxr-xr-x    3 matayoshi matayoshi   77  4月 15 16:03 matayoshi
drwxr-xr-x    3 matsubara matsubara   77  4月 15 16:03 matsubara
drwxr-xr-x    3 mimura    mimura      77  4月 15 16:03 mimura
drwxr-xr-x    3 mitani    mitani      77  4月 15 16:03 mitani
drwxr-xr-x    3 mitsui    mitsui      77  4月 15 16:03 mitsui
drwxr-xr-x    3 momoki    momoki      77  4月 15 16:03 momoki
drwxr-xr-x    3 murata    murata      77  4月 15 16:03 murata
drwxr-xr-x    3 mutou     mutou       77  4月 15 16:03 mutou
drwxr-xr-x    3 naitou    naitou      77  4月 15 16:03 naitou
drwxr-xr-x    3 nakai     nakai       77  4月 15 16:03 nakai
drwxr-xr-x    3 nakajima  nakajima    77  4月 15 16:03 nakajima
drwxr-xr-x    3 narumi    narumi      77  4月 15 16:03 narumi
drwxr-xr-x    3 nemoto    nemoto      77  4月 15 16:03 nemoto
drwxr-xr-x    3 nishikawa nishikawa   77  4月 15 16:03 nishikawa
drwxr-xr-x    3 nishino   nishino     77  4月 15 16:03 nishino
drwxr-xr-x    3 nomura    nomura      77  4月 15 16:03 nomura
drwxr-xr-x    3 nozaki    nozaki      77  4月 15 16:03 nozaki
drwxr-xr-x    3 numata    numata      77  4月 15 16:03 numata
drwxrwxrwx    5 obuchi    obuchi     170  4月 15 16:05 obuchi
drwxr-xr-x    3 oda       oda         77  4月 15 16:03 oda
drwxr-xr-x    3 ogawa     ogawa       77  4月 15 16:03 ogawa
drwxr-xr-x    3 okada     okada       77  4月 15 16:03 okada
drwxr-xr-x    3 onoda     onoda       77  4月 15 16:03 onoda
drwxr-xr-x    3 ozeki     ozeki       77  4月 15 16:03 ozeki
drwxr-xr-x    3 sakaguchi sakaguchi   77  4月 15 16:03 sakaguchi
drwxr-xr-x    3 sakai     sakai       77  4月 15 16:03 sakai
drwxr-xr-x    3 sawamura  sawamura    77  4月 15 16:03 sawamura
drwxr-xr-x    3 sera      sera        77  4月 15 16:03 sera
drwxr-xr-x    3 shibata   shibata     77  4月 15 16:03 shibata
drwxr-xr-x    3 shindou   shindou     77  4月 15 16:03 shindou
drwxr-xr-x    3 sohue     sohue       77  4月 15 16:03 sohue
drwxr-xr-x    3 sugita    sugita      77  4月 15 16:03 sugita
drwxr-xr-x    3 suruga    suruga      77  4月 15 16:03 suruga
drwxr-xr-x    3 suzuki    suzuki      77  4月 15 16:03 suzuki
drwxr-xr-x    3 syouji    syouji      77  4月 15 16:03 syouji
drwxr-xr-x    3 tabata    tabata      77  4月 15 16:03 tabata
drwxr-xr-x    3 tachibana tachibana   77  4月 15 16:03 tachibana
drwxr-xr-x    3 takahashi takahashi   77  4月 15 16:03 takahashi
drwxr-xr-x    3 tamaki    tamaki      77  4月 15 16:03 tamaki
drwxr-xr-x    3 teduka    teduka      77  4月 15 16:03 teduka
drwxr-xr-x    3 terada    terada      77  4月 15 16:03 terada
drwxr-xr-x    3 tokita    tokita      77  4月 15 16:03 tokita
drwxr-xr-x    3 tominaga  tominaga    77  4月 15 16:03 tominaga
drwxr-xr-x    3 toyoda    toyoda      77  4月 15 16:03 toyoda
drwxr-xr-x    3 tsujimoto tsujimoto   77  4月 15 16:03 tsujimoto
drwxr-xr-x    3 tsukahara tsukahara   77  4月 15 16:03 tsukahara
drwxr-xr-x    3 tsuruta   tsuruta     77  4月 15 16:03 tsuruta
drwxr-xr-x    3 ueda      ueda        77  4月 15 16:03 ueda
drwxr-xr-x    3 umino     umino       77  4月 15 16:03 umino
drwxr-xr-x    3 utagawa   utagawa     77  4月 15 16:03 utagawa
drwxr-xr-x    3 wajima    wajima      77  4月 15 16:03 wajima
drwxr-xr-x    3 watanabe  watanabe    77  4月 15 16:03 watanabe
drwxr-xr-x    3 watari    watari      77  4月 15 16:03 watari
drwxr-xr-x    3 yagi      yagi        77  4月 15 16:03 yagi
drwxr-xr-x    3 yajima    yajima      77  4月 15 16:03 yajima
drwxr-xr-x    3 yamada    yamada      77  4月 15 16:03 yamada
drwxr-xr-x    3 yoshida   yoshida     77  4月 15 16:03 yoshida
drwxr-xr-x    3 yoshikawa yoshikawa   77  4月 15 16:03 yoshikawa
drwxr-xr-x    3 yura      yura        77  4月 15 16:03 yura
[manage@victor ~]$ sudo ls -la /root/ 2>/dev/null | head -30
合計 168
dr-xr-x---.  4 root root   4096  4月 15 16:06 .
dr-xr-xr-x. 17 root root    260  4月 15 16:03 ..
-rw-------.  1 root root   1914  4月 24 10:58 .bash_history
-rw-r--r--.  1 root root     18  4月 15 16:03 .bash_logout
-rw-r--r--.  1 root root    176  4月 15 16:03 .bash_profile
-rw-r--r--   1 root root    401  4月 15 16:06 .bashrc
drwx------   2 root root     25  4月 15 16:03 .ssh
drwx------   5 root root     39  4月 15 16:03 Maildir
-rw-------.  1 root root   1249  4月 15 16:03 anaconda-ks.cfg
-rw-r--r--   1 root root      0  4月 15 16:05 install.log
-rw-r--r--   1 root root      0  4月 15 16:05 install.log.syslog
-rw-r--r--   1 root root 146052  4月 15 16:03 nkf-2.1.4-8.el8.x86_64.rpm
[manage@victor ~]$ ls -la /opt/ /srv/ 2>/dev/null
/opt/:
合計 0
drwxr-xr-x.  2 root root   6  4月 15 16:03 .
dr-xr-xr-x. 17 root root 260  4月 15 16:03 ..

/srv/:
合計 0
drwxr-xr-x.  2 root root   6  4月 15 16:03 .
dr-xr-xr-x. 17 root root 260  4月 15 16:03 ..
[manage@victor ~]$ ls /usr/local/ 2>/dev/null
bin  etc  games  include  lib  lib64  libexec  sbin  share  src
[manage@victor ~]$ rpm -qa | sort > /tmp/victor_rpm_all.txt
[manage@victor ~]$ wc -l /tmp/victor_rpm_all.txt
636 /tmp/victor_rpm_all.txt
[manage@victor ~]$ rpm -qa | grep -iE 'httpd|php|maria|dovecot|sendmail|dhcp|bind|snmp|squid|telnet|rainloop' | sort
bind-export-libs-9.11.36-16.el8_10.6.x86_64
bind-libs-9.11.36-16.el8_10.6.x86_64
bind-libs-lite-9.11.36-16.el8_10.6.x86_64
bind-license-9.11.36-16.el8_10.6.noarch
bind-utils-9.11.36-16.el8_10.6.x86_64
dhcp-common-4.3.6-50.el8_10.noarch
dhcp-libs-4.3.6-50.el8_10.x86_64
dhcp-server-4.3.6-50.el8_10.x86_64
dovecot-2.3.16-6.el8_10.x86_64
httpd-2.4.37-65.module+el8.10.0+40053+5a18018e.7.x86_64
httpd-filesystem-2.4.37-65.module+el8.10.0+40053+5a18018e.7.noarch
httpd-tools-2.4.37-65.module+el8.10.0+40053+5a18018e.7.x86_64
mariadb-10.3.39-2.module+el8.10.0+40062+b4bfe4b1.x86_64
mariadb-backup-10.3.39-2.module+el8.10.0+40062+b4bfe4b1.x86_64
mariadb-common-10.3.39-2.module+el8.10.0+40062+b4bfe4b1.x86_64
mariadb-connector-c-3.1.11-2.el8_3.x86_64
mariadb-connector-c-config-3.1.11-2.el8_3.noarch
mariadb-errmsg-10.3.39-2.module+el8.10.0+40062+b4bfe4b1.x86_64
mariadb-gssapi-server-10.3.39-2.module+el8.10.0+40062+b4bfe4b1.x86_64
mariadb-server-10.3.39-2.module+el8.10.0+40062+b4bfe4b1.x86_64
mariadb-server-utils-10.3.39-2.module+el8.10.0+40062+b4bfe4b1.x86_64
net-snmp-5.8-33.el8_10.x86_64
net-snmp-agent-libs-5.8-33.el8_10.x86_64
net-snmp-libs-5.8-33.el8_10.x86_64
net-snmp-utils-5.8-33.el8_10.x86_64
perl-SNMP_Session-1.13-17.el8.noarch
php-7.2.24-1.module+el8.4.0+413+c9202dda.x86_64
php-cli-7.2.24-1.module+el8.4.0+413+c9202dda.x86_64
php-common-7.2.24-1.module+el8.4.0+413+c9202dda.x86_64
php-devel-7.2.24-1.module+el8.4.0+413+c9202dda.x86_64
php-fpm-7.2.24-1.module+el8.4.0+413+c9202dda.x86_64
php-json-7.2.24-1.module+el8.4.0+413+c9202dda.x86_64
php-mbstring-7.2.24-1.module+el8.4.0+413+c9202dda.x86_64
php-mysqlnd-7.2.24-1.module+el8.4.0+413+c9202dda.x86_64
php-pdo-7.2.24-1.module+el8.4.0+413+c9202dda.x86_64
php-xml-7.2.24-1.module+el8.4.0+413+c9202dda.x86_64
python3-bind-9.11.36-16.el8_10.6.noarch
rocky-logos-httpd-86.3-1.el8.noarch
sendmail-8.15.2-34.el8.x86_64
sendmail-cf-8.15.2-34.el8.noarch
squid-4.15-10.module+el8.10.0+2080+49064dbd.9.x86_64
telnet-0.17-76.el8.x86_64
telnet-server-0.17-76.el8.x86_64
[manage@victor ~]$ sudo dnf history 2>/dev/null | head -30
ID     | コマンドライン                                                                                                                                             | 日時             | 動作           | 変更さ 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    27 | groupinstall Networking Tools                                                                                                                              | 2026-04-15 16:01 | Install        |   13   
    26 | -y install php-devel                                                                                                                                       | 2026-04-15 16:00 | Install        |   20   
    25 | -y install net-snmp net-snmp-utils mrtg                                                                                                                    | 2026-04-15 15:58 | Install        |   32   
    24 | install -y yum                                                                                                                                             | 2026-03-10 02:55 | I, U           |    7   
    23 | install rsync                                                                                                                                              | 2026-03-10 02:55 | Upgrade        |    1   
    22 | install squid                                                                                                                                              | 2026-03-10 02:55 | Install        |    4   
    21 | install bind-utils                                                                                                                                         | 2026-03-10 02:54 | Install        |   11   
    20 | install php-json                                                                                                                                           | 2026-03-10 02:19 | Install        |    1   
    19 | install php-xml                                                                                                                                            | 2026-03-10 01:29 | Install        |    2   
    18 | install unzip                                                                                                                                              | 2026-03-10 01:26 | Upgrade        |    1   
    17 | install vim-enhanced                                                                                                                                       | 2026-03-10 01:17 | Install        |    4   
    16 | install openssh-clients                                                                                                                                    | 2026-03-10 00:43 | Upgrade        |    3   
    15 | install dhcp-server                                                                                                                                        | 2026-03-09 23:18 | Install        |    4   
    14 | install rsyslog                                                                                                                                            | 2026-03-09 22:59 | Install        |    3   
    13 | localinstall ./nkf-2.1.4-8.el8.x86_64.rpm                                                                                                                  | 2026-03-09 22:40 | Install        |    1   
    12 | -y install wget                                                                                                                                            | 2026-03-09 22:38 | Install        |    2   
    11 | install dovecot                                                                                                                                            | 2026-03-09 21:53 | Install        |    2   
    10 | install sendmail-cf                                                                                                                                        | 2026-03-09 21:45 | Install        |    2   
     9 | install sendmail                                                                                                                                           | 2026-03-09 21:33 | Install        |    3   
     8 | install php-mysqlnd                                                                                                                                        | 2026-03-09 21:33 | Install        |    2   
     7 | install mariadb-server                                                                                                                                     | 2026-03-09 20:30 | Install        |   54   
     6 | install php php-mbstring                                                                                                                                   | 2026-03-09 18:47 | Install        |    6   
     5 | install httpd                                                                                                                                              | 2026-03-09 18:47 | Install        |    9   
     4 | install telnet-server                                                                                                                                      | 2026-03-09 18:29 | Install        |    1   
     3 | install telnet                                                                                                                                             | 2026-03-09 18:28 | Install        |    1   
     2 | install chrony                                                                                                                                             | 2026-03-09 17:23 | Upgrade        |    1   
     1 |                                                                                                                                                            | 2026-03-09 16:17 | Install        |  462 EE
[manage@victor ~]$ uname -a
Linux victor.com6.local 4.18.0-553.el8_10.x86_64 #1 SMP Fri May 24 13:05:10 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
[manage@victor ~]$ lsmod | head -20
Module                  Size  Used by
nf_tables             192512  0
nfnetlink              16384  1 nf_tables
tcp_diag               16384  0
udp_diag               16384  0
inet_diag              24576  2 tcp_diag,udp_diag
binfmt_misc            24576  1
bochs                  16384  0
drm_vram_helper        20480  1 bochs
drm_ttm_helper         16384  2 bochs,drm_vram_helper
ttm                    81920  2 drm_vram_helper,drm_ttm_helper
drm_kms_helper        184320  4 bochs,drm_vram_helper
syscopyarea            16384  1 drm_kms_helper
sysfillrect            16384  1 drm_kms_helper
sysimgblt              16384  1 drm_kms_helper
drm                   602112  6 drm_kms_helper,bochs,drm_vram_helper,drm_ttm_helper,ttm
i2c_piix4              24576  0
pcspkr                 16384  0
joydev                 24576  0
virtio_balloon         20480  0
[manage@victor ~]$ echo "=== httpd.conf (no comments) ===" && sudo grep -vE '^\s*#|^\s*$' /etc/httpd/conf/httpd.conf
=== httpd.conf (no comments) ===
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin root@localhost
<Directory />
    Options FollowSymLinks ExecCGI
    AllowOverride All
</Directory>
DocumentRoot "/var/www/wordpress"
<Directory "/var/www">
    AllowOverride None
    Require all granted
</Directory>
<Directory "/var/www/html">
    Options Includes ExecCGI FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
<IfModule dir_module>
    DirectoryIndex index.php index.html
</IfModule>
<Files ".ht*">
    Require all denied
</Files>
ErrorLog "logs/error_log"
LogLevel warn
<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common
    <IfModule logio_module>
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O" combinedio
    </IfModule>
    CustomLog "logs/access_log" combined
</IfModule>
<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
</IfModule>
<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>
<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddHandler cgi-script .cgi .pi
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>
<IfModule mime_magic_module>
    MIMEMagicFile conf/magic
</IfModule>
EnableSendfile on
IncludeOptional conf.d/*.conf
ServerTokens Prod
Alias /rain /var/www/rain
<Directory /var/www/rain/data>
	Order allow,deny
	Deny from all
</Directory>
[manage@victor ~]$ for f in /etc/httpd/conf.d/*.conf; do
>   echo "=== $f ==="; sudo grep -vE '^\s*#|^\s*$' "$f"
> done
=== /etc/httpd/conf.d/autoindex.conf ===
IndexOptions FancyIndexing HTMLTable VersionSort
Alias /icons/ "/usr/share/httpd/icons/"
<Directory "/usr/share/httpd/icons">
    Options MultiViews
    AllowOverride None
    Require all granted
</Directory>
AddIconByEncoding (CMP,/icons/compressed.gif) x-compress x-gzip
AddIconByType (TXT,/icons/text.gif) text/*
AddIconByType (IMG,/icons/image2.gif) image/*
AddIconByType (SND,/icons/sound2.gif) audio/*
AddIconByType (VID,/icons/movie.gif) video/*
AddIcon /icons/binary.gif .bin .exe
AddIcon /icons/binhex.gif .hqx
AddIcon /icons/tar.gif .tar
AddIcon /icons/world2.gif .wrl .wrl.gz .vrml .vrm .iv
AddIcon /icons/compressed.gif .Z .z .tgz .gz .zip
AddIcon /icons/a.gif .ps .ai .eps
AddIcon /icons/layout.gif .html .shtml .htm .pdf
AddIcon /icons/text.gif .txt
AddIcon /icons/c.gif .c
AddIcon /icons/p.gif .pl .py
AddIcon /icons/f.gif .for
AddIcon /icons/dvi.gif .dvi
AddIcon /icons/uuencoded.gif .uu
AddIcon /icons/script.gif .conf .sh .shar .csh .ksh .tcl
AddIcon /icons/tex.gif .tex
AddIcon /icons/bomb.gif /core
AddIcon /icons/bomb.gif */core.*
AddIcon /icons/back.gif ..
AddIcon /icons/hand.right.gif README
AddIcon /icons/folder.gif ^^DIRECTORY^^
AddIcon /icons/blank.gif ^^BLANKICON^^
DefaultIcon /icons/unknown.gif
ReadmeName README.html
HeaderName HEADER.html
IndexIgnore .??* *~ *# HEADER* README* RCS CVS *,v *,t
=== /etc/httpd/conf.d/mrtg.conf ===
Alias /mrtg /var/www/mrtg
=== /etc/httpd/conf.d/php.conf ===
<Files ".user.ini">
    Require all denied
</Files>
AddType text/html .php
DirectoryIndex index.php
<IfModule !mod_php5.c>
  <IfModule !mod_php7.c>
    SetEnvIfNoCase ^Authorization$ "(.+)" HTTP_AUTHORIZATION=$1
    <FilesMatch \.(php|phar)$>
        SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost"
    </FilesMatch>
  </IfModule>
</IfModule>
<IfModule  mod_php7.c>
    <FilesMatch \.(php|phar)$>
        SetHandler application/x-httpd-php
    </FilesMatch>
    php_value session.save_handler "files"
    php_value session.save_path    "/var/lib/php/session"
    php_value soap.wsdl_cache_dir  "/var/lib/php/wsdlcache"
</IfModule>
=== /etc/httpd/conf.d/squid.conf ===
ScriptAlias /Squid/cgi-bin/cachemgr.cgi /usr/lib64/squid/cachemgr.cgi
<Location /Squid/cgi-bin/cachemgr.cgi>
 Require local
</Location>
=== /etc/httpd/conf.d/userdir.conf ===
<IfModule mod_userdir.c>
    UserDir disabled
</IfModule>
<Directory "/home/*/public_html">
    AllowOverride FileInfo AuthConfig Limit Indexes
    Options MultiViews Indexes SymLinksIfOwnerMatch IncludesNoExec
    Require method GET POST OPTIONS
</Directory>
=== /etc/httpd/conf.d/welcome.conf ===
<LocationMatch "^/+$">
    Options -Indexes
    ErrorDocument 403 /.noindex.html
</LocationMatch>
<Directory /usr/share/httpd/noindex>
    AllowOverride None
    Require all granted
</Directory>
Alias /.noindex.html /usr/share/httpd/noindex/index.html
Alias /poweredby.png /usr/share/httpd/icons/apache_pb3.png
[manage@victor ~]$ sudo doveconf -n 2>/dev/null || sudo grep -rvE '^\s*#|^\s*$' /etc/dovecot/ 2>/dev/null | head -80
# 2.3.16 (7e2e900c1a): /etc/dovecot/dovecot.conf
# OS: Linux 4.18.0-553.el8_10.x86_64 x86_64 Rocky Linux release 8.10 (Green Obsidian) 
# Hostname: victor.com6.local
first_valid_uid = 1000
mail_location = maildir:~/Maildir
mbox_write_locks = fcntl
namespace inbox {
  inbox = yes
  location = 
  mailbox Drafts {
    special_use = \Drafts
  }
  mailbox Junk {
    special_use = \Junk
  }
  mailbox Sent {
    special_use = \Sent
  }
  mailbox "Sent Messages" {
    special_use = \Sent
  }
  mailbox Trash {
    special_use = \Trash
  }
  prefix = 
}
passdb {
  driver = pam
}
protocols = imap
ssl = required
ssl_cert = </etc/pki/dovecot/certs/dovecot.pem
ssl_cipher_list = PROFILE=SYSTEM
ssl_key = # hidden, use -P to show it
userdb {
  driver = passwd
}
[manage@victor ~]$ sudo grep -E '^[A-Z]' /etc/mail/sendmail.cf | head -40
V10/Berkeley
Cwlocalhost
Fw/etc/mail/local-host-names
CP.
DS
CO @ % !
C..
C[[
C{Accept}OK RELAY
C{ResOk}OKR
FR-o /etc/mail/relay-domains
Karith arith
Kmacro macro
C{Tls}VERIFY ENCR
Kdequote dequote
C{E}root
C{w}com6.local
DnMAILER-DAEMON
Kmailertable hash -o /etc/mail/mailertable.db
Kvirtuser hash -o /etc/mail/virtusertable.db
CPREDIRECT
Kaccess hash -T<TMPF> -o /etc/mail/access.db
DZ8.15.2
O SevenBitInput=False
O AliasWait=10
O AliasFile=/etc/aliases
O MinFreeBlocks=100
O BlankSub=.
O HoldExpensive=False
O DeliveryMode=background
O TempFileMode=0600
O HelpFile=/etc/mail/helpfile
O SendMimeErrors=True
O ForwardPath=$z/.forward.$w:$z/.forward
O ConnectionCacheSize=2
O ConnectionCacheTimeout=5m
O UseErrorsTo=False
O LogLevel=9
O CheckAliases=False
O OldStyleHeaders=True
[manage@victor ~]$ sudo ls /etc/mail/
Makefile  access.db	   domaintable	   helpfile	     mailertable     make	  sendmail.cf.bak  submit.cf	  submit.mc	 virtusertable
access	  aliasesdb-stamp  domaintable.db  local-host-names  mailertable.db  sendmail.cf  sendmail.mc	   submit.cf.bak  trusted-users  virtusertable.db
[manage@victor ~]$ cat /etc/aliases 2>/dev/null | grep -v '^#' | grep -v '^$' | head -30
mailer-daemon:	postmaster
postmaster:	root
bin:		root
daemon:		root
adm:		root
lp:		root
sync:		root
shutdown:	root
halt:		root
mail:		root
news:		root
uucp:		root
operator:	root
games:		root
gopher:		root
ftp:		root
nobody:		root
radiusd:	root
nut:		root
dbus:		root
vcsa:		root
canna:		root
wnn:		root
rpm:		root
nscd:		root
pcap:		root
apache:		root
webalizer:	root
dovecot:	root
fax:		root
[manage@victor ~]$ sudo grep -vE '^\s*#|^\s*$' /etc/snmp/snmpd.conf
com2sec notConfigUser  default       public
group   notConfigGroup v1           notConfigUser
group   notConfigGroup v2c           notConfigUser
view    systemview    included   .1.3.6.1.2.1.1
view    systemview    included   .1.3.6.1.2.1.25.1.1
access  notConfigGroup ""      any       noauth    exact  systemview none none
syslocation Unknown (edit /etc/snmp/snmpd.conf)
syscontact Root <root@localhost> (configure /etc/snmp/snmp.local.conf)
dontLogTCPWrappersConnects yes
[manage@victor ~]$ sudo grep -vE '^\s*#|^\s*$' /etc/dhcp/dhcpd.conf
option domain-name "com6.local";
option domain-name-servers 10.1.6.1;
ddns-update-style interim;
ignore client-updates;
not authoritative;
log-facility local3;
subnet 10.1.16.0 netmask 255.255.255.0 {
	option broadcast-address 10.1.16.255;
	option routers                  10.1.16.254;
	option subnet-mask              255.255.255.0;
	range dynamic-bootp             10.1.16.50 10.1.16.99;
}
zone com6.local {
	primary 10.1.6.1;
}
zone 16.1.10.in-add.arpa{
	primary 10.1.6.1;
}
subnet 10.1.6.0 netmask 255.255.255.0{
}
[manage@victor ~]$ sudo ls -la /var/lib/dhcpd/ 2>/dev/null
合計 12
drwxr-xr-x   2 dhcpd dhcpd   68  4月 24 00:32 .
drwxr-xr-x. 40 root  root  4096  4月 15 16:03 ..
-rw-r--r--   1 dhcpd dhcpd  280  4月 24 00:32 dhcpd.leases
-rw-r--r--   1 dhcpd dhcpd  280  4月 23 18:10 dhcpd.leases~
-rw-r--r--   1 dhcpd dhcpd    0  4月 15 16:03 dhcpd6.leases
[manage@victor ~]$ sudo tail -30 /var/lib/dhcpd/dhcpd.leases 2>/dev/null
# The format of this file is documented in the dhcpd.leases(5) manual page.
# This lease file was written by isc-dhcp-4.3.6

# authoring-byte-order entry is generated, DO NOT DELETE
authoring-byte-order little-endian;

server-duid "\000\001\000\0011|\236\213\274$\021\243\212p";

[manage@victor ~]$ systemctl list-sockets --all | grep -i telnet
[::]:23                           telnet.socket                   telnet@0.service
[manage@victor ~]$ ls /etc/xinetd.d/ 2>/dev/null
[manage@victor ~]$ systemctl cat telnet.socket 2>/dev/null | head -20
# /usr/lib/systemd/system/telnet.socket
[Unit]
Description=Telnet Server Activation Socket
Documentation=man:telnetd(8)

[Socket]
ListenStream=23
Accept=true

[Install]
WantedBy=sockets.target
[manage@victor ~]$ sudo ss -ulnp | grep 34020
UNCONN 0      0            0.0.0.0:34020      0.0.0.0:*    users:(("dhcpd",pid=927,fd=20))  
[manage@victor ~]$ sudo lsof -i UDP:34020 2>/dev/null
COMMAND PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
dhcpd   927 dhcpd   20u  IPv4  24802      0t0  UDP *:34020 
[manage@victor ~]$ ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
/etc/cron.d/:
合計 24
drwxr-xr-x.   2 root root   51  4月 15 16:03 .
drwxr-xr-x. 101 root root 8192  4月 24 00:32 ..
-rw-r--r--.   1 root root  128  4月 15 16:03 0hourly
-rw-r--r--    1 root root  139  4月 15 16:03 mrtg
-rw-r--r--.   1 root root  108  4月 15 16:03 raid-check

/etc/cron.daily/:
合計 16
drwxr-xr-x.   2 root root   23  4月 15 16:03 .
drwxr-xr-x. 101 root root 8192  4月 24 00:32 ..
-rwxr-xr-x.   1 root root  189  4月 15 16:03 logrotate

/etc/cron.hourly/:
合計 16
drwxr-xr-x.   2 root root   22  4月 15 16:03 .
drwxr-xr-x. 101 root root 8192  4月 24 00:32 ..
-rwxr-xr-x.   1 root root  575  4月 15 16:03 0anacron

/etc/cron.monthly/:
合計 12
drwxr-xr-x.   2 root root    6  4月 15 16:03 .
drwxr-xr-x. 101 root root 8192  4月 24 00:32 ..

/etc/cron.weekly/:
合計 12
drwxr-xr-x.   2 root root    6  4月 15 16:03 .
drwxr-xr-x. 101 root root 8192  4月 24 00:32 ..
[manage@victor ~]$ cat /etc/crontab 2>/dev/null
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed

[manage@victor ~]$ sudo ls -la /var/spool/cron/
合計 0
drwx------.  2 root root   6  4月 15 16:03 .
drwxr-xr-x. 10 root root 113  4月 15 16:03 ..
[manage@victor ~]$ for u in $(sudo ls /var/spool/cron/ 2>/dev/null); do
>   echo "--- cron of $u ---"; sudo cat /var/spool/cron/$u
> donesystemctl list-timers --all
> 
> php -i 2>/dev/null | grep -iE 'expose_php|display_errors|allow_url_(include|fopen)|open_basedir|disable_functions|short_open_tag|memory_limit|post_max_size' | sort -u
> bash
> ^C
[manage@victor ~]$ php -i 2>/dev/null | grep -iE 'expose_php|display_errors|allow_url_(include|fopen)|open_basedir|disable_functions|short_open_tag|memory_limit|post_max_size' | sort -u
allow_url_fopen => On => On
allow_url_include => Off => Off
disable_functions => no value => no value
display_errors => Off => Off
expose_php => On => On
memory_limit => 128M => 128M
open_basedir => no value => no value
post_max_size => 8M => 8M
short_open_tag => On => On
[manage@victor ~]$ ip -br a
lo               UNKNOWN        127.0.0.1/8 ::1/128 
ens18            UP             10.1.6.2/24 fe80::be24:11ff:fea3:8a70/64 
[manage@victor ~]$ ip route
default via 10.1.6.254 dev ens18 proto static metric 100 
10.1.6.0/24 dev ens18 proto kernel scope link src 10.1.6.2 metric 100 
[manage@victor ~]$ cat /etc/resolv.conf
# Generated by NetworkManager
search com6.local
nameserver 10.1.6.1
[manage@victor ~]$ cat /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
[manage@victor ~]$ cat /var/www/wordpress/wp-includes/version.php | grep wp_version
 * @global string $wp_version
$wp_version = '4.9.4';
[manage@victor ~]$ ls /var/www/wordpress/wp-content/plugins/
akismet  hello.php  index.php  wp-multibyte-patch
[manage@victor ~]$ ls /var/www/wordpress/wp-content/themes/
index.php  twentyeleven  twentyfifteen  twentyseventeen  twentysixteen
[manage@victor ~]$ sudo ls -la /var/www/wordpress/wp-config.php
[sudo] manage のパスワード:
残念、また試してください。
[sudo] manage のパスワード:
-rw-r--r-- 1 apache apache 3868  4月 15 16:03 /var/www/wordpress/wp-config.php
[manage@victor ~]$ head -30 /var/www/rain/index.php
<?php

if (!defined('APP_VERSION'))
{
	define('APP_VERSION', '1.12.0');
	define('APP_VERSION_TYPE', 'standard');
	define('APP_INDEX_ROOT_FILE', __FILE__);
	define('APP_INDEX_ROOT_PATH', str_replace('\\', '/', rtrim(dirname(__FILE__), '\\/').'/'));
}

if (file_exists(APP_INDEX_ROOT_PATH.'rainloop/v/'.APP_VERSION.'/include.php'))
{
	include APP_INDEX_ROOT_PATH.'rainloop/v/'.APP_VERSION.'/include.php';
}
else
{
	echo '[105] Missing version directory';
	exit(105);
}
[manage@victor ~]$ ls /var/www/rain/data/ 2>/dev/null
EMPTY  INSTALLED  SALT.php  VERSION  _data_  index.html  index.php
[manage@victor ~]$ find /var/www/rain -maxdepth 5 -name 'VERSION' 2>/dev/null
/var/www/rain/data/VERSION
[manage@victor ~]$ find /var/www/rain -maxdepth 6 -iname 'index.php' 2>/dev/null
/var/www/rain/data/index.php
/var/www/rain/index.php
/var/www/rain/rainloop/v/1.12.0/index.php
[manage@victor ~]$ ls /var/www/backup_html/ | head -30
bbs
bbs_admin
business
careers
conf.cgi
history
img
index.html
log.dat
member
search.cgi
search.html
stock
[manage@victor ~]$ diff -rq /var/www/wordpress /var/www/backup_html 2>/dev/null | head -40
/var/www/wordpress のみに存在: .htaccess
/var/www/wordpress のみに存在: index.php
/var/www/wordpress のみに存在: license.txt
/var/www/wordpress のみに存在: readme.html
/var/www/wordpress のみに存在: wp-activate.php
/var/www/wordpress のみに存在: wp-admin
/var/www/wordpress のみに存在: wp-blog-header.php
/var/www/wordpress のみに存在: wp-comments-post.php
/var/www/wordpress のみに存在: wp-config.php
/var/www/wordpress のみに存在: wp-content
/var/www/wordpress のみに存在: wp-cron.php
/var/www/wordpress のみに存在: wp-includes
/var/www/wordpress のみに存在: wp-links-opml.php
/var/www/wordpress のみに存在: wp-load.php
/var/www/wordpress のみに存在: wp-login.php
/var/www/wordpress のみに存在: wp-mail.php
/var/www/wordpress のみに存在: wp-settings.php
/var/www/wordpress のみに存在: wp-signup.php
/var/www/wordpress のみに存在: wp-trackback.php
/var/www/wordpress のみに存在: xmlrpc.php
[manage@victor ~]$ sudo find /var/www /etc /usr/local -type f -mtime -30 2>/dev/null | head -60
/var/www/cgi-bin/.my.cnf.6804
/var/www/cgi-bin/.mysql.6804
/var/www/rain/data/EMPTY
/var/www/rain/data/VERSION
/var/www/rain/data/SALT.php
/var/www/rain/data/INSTALLED
/var/www/rain/data/index.html
/var/www/rain/data/index.php
/var/www/rain/data/_data_/_default_/cache/47/91/47916b7ebf0d20007ea6d25a6ef9f42af2a65641
/var/www/rain/data/_data_/_default_/cache/2c/61/2c61bfdf22f78c5b8c1a793cf350f54a5ed54885
/var/www/rain/data/_data_/_default_/cache/e7/ce/e7ce5587bbda05a75c27ebe08e1309a93680d2c9
/var/www/rain/data/_data_/_default_/cache/6c/46/6c46d99e59ee099592e9be744ea70c17d70f662b
/var/www/rain/data/_data_/_default_/cache/81/ab/81abffd6440b99bdcca020e1b9c49466f5ada7e1
/var/www/rain/data/_data_/_default_/cache/0e/ea/0eead3b7915dbc1924dee134aa7ad5660722c11a
/var/www/rain/data/_data_/_default_/configs/application.ini
/var/www/rain/data/_data_/_default_/storage/cfg/ma/manage@com1.local/sign_me
/var/www/rain/data/_data_/_default_/storage/cfg/ma/manage@com1.local/settings_local
/var/www/rain/data/_data_/_default_/storage/cfg/ma/manage@com6.local/settings_local
/var/www/rain/data/_data_/_default_/storage/cfg/ak/akagi@com1.local/settings_local
/var/www/rain/data/_data_/_default_/storage/cfg/is/ishikawa@com1.local/settings_local
/var/www/rain/data/_data_/_default_/storage/cfg/ka/katsura@service.com1.local/settings_local
/var/www/rain/data/_data_/_default_/storage/data/__nobody__/ef/efaeb36a60ef9682802c6a704c2d784d
/var/www/rain/data/_data_/_default_/domains/disabled
/var/www/rain/data/_data_/_default_/domains/gmail.com.ini
/var/www/rain/data/_data_/_default_/domains/outlook.com.ini
/var/www/rain/data/_data_/_default_/domains/qq.com.ini
/var/www/rain/data/_data_/_default_/domains/yahoo.com.ini
/var/www/rain/data/_data_/_default_/domains/com6.local.ini
/var/www/rain/data/_data_/_default_/domains/service.com6.local.ini
/var/www/rain/index.php
/var/www/rain/rainloop/v/1.12.0/app/domains/default.ini.dist
/var/www/rain/rainloop/v/1.12.0/app/domains/disabled
/var/www/rain/rainloop/v/1.12.0/app/domains/gmail.com.ini
/var/www/rain/rainloop/v/1.12.0/app/domains/outlook.com.ini
/var/www/rain/rainloop/v/1.12.0/app/domains/qq.com.ini
/var/www/rain/rainloop/v/1.12.0/app/domains/yahoo.com.ini
/var/www/rain/rainloop/v/1.12.0/app/handle.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Authentication/AccessToken.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Authentication/AccessTokenMetadata.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Authentication/OAuth2Client.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Exceptions/FacebookAuthenticationException.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Exceptions/FacebookAuthorizationException.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Exceptions/FacebookClientException.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Exceptions/FacebookOtherException.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Exceptions/FacebookResponseException.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Exceptions/FacebookSDKException.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Exceptions/FacebookServerException.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Exceptions/FacebookThrottleException.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/Facebook.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/FacebookApp.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/FacebookBatchRequest.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/FacebookBatchResponse.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/FacebookClient.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/FacebookRequest.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/FacebookResponse.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/FileUpload/FacebookFile.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/FileUpload/FacebookVideo.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/FileUpload/Mimetypes.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/GraphNodes/Collection.php
/var/www/rain/rainloop/v/1.12.0/app/libraries/Facebook/GraphNodes/GraphAchievement.php
[manage@victor ~]$ sudo find / -xdev -perm -4000 -type f 2>/dev/null | sort > /tmp/victor_suid.txt
[manage@victor ~]$ wc -l /tmp/victor_suid.txt
23 /tmp/victor_suid.txt
[manage@victor ~]$ cat /tmp/victor_suid.txt
/usr/bin/at
/usr/bin/chage
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/cockpit-session
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/sssd/krb5_child
/usr/libexec/sssd/ldap_child
/usr/libexec/sssd/proxy_child
/usr/libexec/sssd/selinux_child
/usr/sbin/grub2-set-bootflag
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
[manage@victor ~]$ awk -F: '$3 >= 1000 || $1 == "root" {print $1":"$3":"$6":"$7}' /etc/passwd
root:0:/root:/bin/bash
nobody:65534:/:/sbin/nologin
aizawa:1001:/home/aizawa:/bin/bash
akagi:1002:/home/akagi:/bin/bash
arai:1003:/home/arai:/bin/bash
amano:1004:/home/amano:/bin/bash
amuro:1005:/home/amuro:/bin/bash
ishikawa:1006:/home/ishikawa:/bin/bash
ishibashi:1007:/home/ishibashi:/bin/bash
itou:1008:/home/itou:/bin/bash
ichihara:1009:/home/ichihara:/bin/bash
imamura:1010:/home/imamura:/bin/bash
irino:1011:/home/irino:/bin/bash
ueda:1012:/home/ueda:/bin/bash
utagawa:1013:/home/utagawa:/bin/bash
umino:1014:/home/umino:/bin/bash
etou:1015:/home/etou:/bin/bash
egawa:1016:/home/egawa:/bin/bash
okada:1017:/home/okada:/bin/bash
ogawa:1018:/home/ogawa:/bin/bash
ozeki:1019:/home/ozeki:/bin/bash
oda:1020:/home/oda:/bin/bash
onoda:1021:/home/onoda:/bin/bash
kai:1022:/home/kai:/bin/bash
kagawa:1023:/home/kagawa:/bin/bash
katakura:1024:/home/katakura:/bin/bash
kanemoto:1025:/home/kanemoto:/bin/bash
kamei:1026:/home/kamei:/bin/bash
karasawa:1027:/home/karasawa:/bin/bash
kawamura:1028:/home/kawamura:/bin/bash
kitajima:1029:/home/kitajima:/bin/bash
kimino:1030:/home/kimino:/bin/bash
kira:1031:/home/kira:/bin/bash
kindaichi:1032:/home/kindaichi:/bin/bash
kudou:1033:/home/kudou:/bin/bash
kumazawa:1034:/home/kumazawa:/bin/bash
kobayashi:1035:/home/kobayashi:/bin/bash
komiyama:1036:/home/komiyama:/bin/bash
sakai:1037:/home/sakai:/bin/bash
sakaguchi:1038:/home/sakaguchi:/bin/bash
sawamura:1039:/home/sawamura:/bin/bash
shibata:1040:/home/shibata:/bin/bash
shindou:1041:/home/shindou:/bin/bash
syouji:1042:/home/syouji:/bin/bash
sugita:1043:/home/sugita:/bin/bash
suzuki:1044:/home/suzuki:/bin/bash
suruga:1045:/home/suruga:/bin/bash
sera:1046:/home/sera:/bin/bash
sohue:1047:/home/sohue:/bin/bash
takahashi:1048:/home/takahashi:/bin/bash
tachibana:1049:/home/tachibana:/bin/bash
tabata:1050:/home/tabata:/bin/bash
tamaki:1051:/home/tamaki:/bin/bash
chida:1052:/home/chida:/bin/bash
tsukahara:1053:/home/tsukahara:/bin/bash
tsujimoto:1054:/home/tsujimoto:/bin/bash
tsuruta:1055:/home/tsuruta:/bin/bash
teduka:1056:/home/teduka:/bin/bash
terada:1057:/home/terada:/bin/bash
tokita:1058:/home/tokita:/bin/bash
tominaga:1059:/home/tominaga:/bin/bash
toyoda:1060:/home/toyoda:/bin/bash
naitou:1061:/home/naitou:/bin/bash
nakai:1062:/home/nakai:/bin/bash
nakajima:1063:/home/nakajima:/bin/bash
narumi:1064:/home/narumi:/bin/bash
nishikawa:1065:/home/nishikawa:/bin/bash
nishino:1066:/home/nishino:/bin/bash
numata:1067:/home/numata:/bin/bash
nemoto:1068:/home/nemoto:/bin/bash
nozaki:1069:/home/nozaki:/bin/bash
nomura:1070:/home/nomura:/bin/bash
hara:1071:/home/hara:/bin/bash
hamada:1072:/home/hamada:/bin/bash
higuchi:1073:/home/higuchi:/bin/bash
hirota:1074:/home/hirota:/bin/bash
hukui:1075:/home/hukui:/bin/bash
huruta:1076:/home/huruta:/bin/bash
henmi:1077:/home/henmi:/bin/bash
hoshino:1078:/home/hoshino:/bin/bash
hosomi:1079:/home/hosomi:/bin/bash
horikawa:1080:/home/horikawa:/bin/bash
makita:1081:/home/makita:/bin/bash
matsubara:1082:/home/matsubara:/bin/bash
matayoshi:1083:/home/matayoshi:/bin/bash
maruyama:1084:/home/maruyama:/bin/bash
mitani:1085:/home/mitani:/bin/bash
mitsui:1086:/home/mitsui:/bin/bash
mimura:1087:/home/mimura:/bin/bash
mutou:1088:/home/mutou:/bin/bash
murata:1089:/home/murata:/bin/bash
momoki:1090:/home/momoki:/bin/bash
yagi:1091:/home/yagi:/bin/bash
yajima:1092:/home/yajima:/bin/bash
yamada:1093:/home/yamada:/bin/bash
yura:1094:/home/yura:/bin/bash
yoshikawa:1095:/home/yoshikawa:/bin/bash
yoshida:1096:/home/yoshida:/bin/bash
wajima:1097:/home/wajima:/bin/bash
watanabe:1098:/home/watanabe:/bin/bash
watari:1099:/home/watari:/bin/bash
manage:1100:/home/manage:/bin/bash
obuchi:1101:/home/obuchi:/bin/bash
[manage@victor ~]$ last -n 30
manage   pts/2        10.1.16.12       Fri Apr 24 11:14 - 11:14  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:14 - 11:14  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:12 - 11:12  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:11 - 11:11  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:03 - 11:03  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:03 - 11:03  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:01 - 11:01  (00:00)
manage   pts/4        10.1.16.12       Fri Apr 24 10:50 - 10:55  (00:05)
manage   pts/4        10.1.16.12       Fri Apr 24 10:47 - 10:47  (00:00)
manage   pts/3        10.1.6.1         Fri Apr 24 10:39   still logged in
manage   pts/3        10.1.16.16       Fri Apr 24 10:37 - 10:37  (00:00)
manage   pts/2        10.1.16.15       Fri Apr 24 10:33 - 10:58  (00:24)
manage   pts/2        10.1.16.12       Fri Apr 24 10:31 - 10:32  (00:00)
manage   pts/1        10.1.6.1         Fri Apr 24 09:56   still logged in
manage   pts/1        10.1.6.1         Fri Apr 24 09:51 - 09:54  (00:03)
manage   pts/0        10.1.16.16       Fri Apr 24 08:37   still logged in
manage   pts/0        10.1.16.16       Fri Apr 24 08:32 - 08:33  (00:00)
manage   pts/1        10.1.129.10      Fri Apr 24 01:43 - 04:00  (02:16)
obuchi   pts/0        10.1.129.10      Fri Apr 24 01:40 - 04:00  (02:19)
reboot   system boot  4.18.0-553.el8_1 Fri Apr 24 00:32   still running
root     tty1                          Thu Apr 23 19:07 - 19:07  (00:00)
reboot   system boot  4.18.0-553.el8_1 Thu Apr 23 18:10 - 19:07  (00:56)

wtmp は Wed Apr 15 16:07:01 2026 から始まっています
[manage@victor ~]$ sudo lastlog | grep -v 'Never logged in' | head -20
ユーザ名         ポート   場所             最近のログイン
root             pts/2                     金  4月 24 10:35:38 +0900 2026
bin                                        **一度もログインしていません**
daemon                                     **一度もログインしていません**
adm                                        **一度もログインしていません**
lp                                         **一度もログインしていません**
sync                                       **一度もログインしていません**
shutdown                                   **一度もログインしていません**
halt                                       **一度もログインしていません**
mail                                       **一度もログインしていません**
operator                                   **一度もログインしていません**
games                                      **一度もログインしていません**
ftp                                        **一度もログインしていません**
nobody                                     **一度もログインしていません**
dbus                                       **一度もログインしていません**
systemd-coredump                           **一度もログインしていません**
systemd-resolve                            **一度もログインしていません**
tss                                        **一度もログインしていません**
polkitd                                    **一度もログインしていません**
libstoragemgmt                             **一度もログインしていません**
[manage@victor ~]$ mysql -u root -e "SHOW DATABASES;" 2>/dev/null \
>   || echo '(root パス必要。スキップ)'for db in wordpress rainloop bbs_db; do
-bash: 予期しないトークン `do' 周辺に構文エラーがあります
[manage@victor ~]$   echo "=== $db tables ==="
===  tables ===
[manage@victor ~]$   mysql -u root -e "USE $db; SHOW TABLES;" 2>/dev/null
[manage@victor ~]$ exit
ログアウト
Connection to 10.1.6.2 closed.
> ssh manage@10.1.6.2
manage@10.1.6.2's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Fri Apr 24 11:23:05 2026 from 10.1.16.12
[manage@victor ~]$ ^C
[manage@victor ~]$ exit
ログアウト
Connection to 10.1.6.2 closed.
> ssh manage@10.1.6.2
manage@10.1.6.2's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Fri Apr 24 11:28:24 2026 from 10.1.6.1
[manage@victor ~]$ sudo find / -maxdepth 3 -type d 2>/dev/null > /tmp/bravo_tree_d3.txt
[sudo] manage のパスワード:
[manage@victor ~]$ head -40 /tmp/bravo_tree_d3.txt
/
/boot
/boot/efi
/boot/efi/EFI
/boot/grub2
/boot/grub2/i386-pc
/boot/grub2/fonts
/boot/loader
/boot/loader/entries
/dev
/dev/dri
/dev/dri/by-path
/dev/snd
/dev/vfio
/dev/net
/dev/hugepages
/dev/mqueue
/dev/rl
/dev/disk
/dev/disk/by-label
/dev/disk/by-uuid
/dev/disk/by-partuuid
/dev/disk/by-path
/dev/disk/by-id
/dev/block
/dev/bsg
/dev/char
/dev/mapper
/dev/pts
/dev/shm
/dev/input
/dev/input/by-id
/dev/input/by-path
/dev/bus
/dev/bus/usb
/dev/raw
/dev/cpu
/dev/cpu/1
/dev/cpu/0
/proc
[manage@victor ~]$ sudo find /etc -type f 2>/dev/null > /tmp/bravo_etc_files.txt
[manage@victor ~]$ wc -l /tmp/bravo_etc_files.txt
614 /tmp/bravo_etc_files.txt
[manage@victor ~]$ sudo find /usr/local/etc -maxdepth 4 -type f 2>/dev/null > /tmp/bravo_ulocal_etc.txt
[manage@victor ~]$ wc -l /tmp/bravo_ulocal_etc.txt
0 /tmp/bravo_ulocal_etc.txt
[manage@victor ~]$ sudo find /usr/local/www -maxdepth 5 2>/dev/null > /tmp/bravo_www_tree.txt
[manage@victor ~]$ head -80 /tmp/bravo_www_tree.txt
[manage@victor ~]$ pkg info | head -30
-bash: pkg: コマンドが見つかりません
[manage@victor ~]$ pkg info | wc -l
-bash: pkg: コマンドが見つかりません
0
[manage@victor ~]$ pkg info | grep -iE 'apache|php|mysql|bind|sendmail|courier|postfix'
-bash: pkg: コマンドが見つかりません
[manage@victor ~]$ service -e
The service command supports only basic LSB actions (start, stop, restart, try-restart, reload, force-reload, status). For other actions, please try to use systemctl.
[manage@victor ~]$ cat /etc/rc.conf
cat: /etc/rc.conf: No such file or directory
[manage@victor ~]$ kldstat
-bash: kldstat: コマンドが見つかりません
[manage@victor ~]$ sudo cat /usr/local/etc/namedb/named.conf 2>/dev/null | grep -vE '^\s*//|^\s*#|^\s*$'
[manage@victor ~]$ sudo ls -la /usr/local/etc/namedb/
ls: '/usr/local/etc/namedb/' にアクセスできません: No such file or directory
[manage@victor ~]$ for z in $(sudo grep -E '^\s*file' /usr/local/etc/namedb/named.conf | awk -F\" '{print $2}'); do
>   echo "=== zone file: $z ==="
>   sudo cat "/usr/local/etc/namedb/$z" 2>/dev/null \
>     || sudo cat "$z" 2>/dev/null
> done
grep: /usr/local/etc/namedb/named.conf: No such file or directory
[manage@victor ~]$ sudo grep -vE '^\s*#|^\s*$' /usr/local/etc/apache24/httpd.conf | head -80
grep: /usr/local/etc/apache24/httpd.conf: No such file or directory
[manage@victor ~]$ sudo ls /usr/local/etc/apache24/
ls: '/usr/local/etc/apache24/' にアクセスできません: No such file or directory
[manage@victor ~]$ sudo ls /usr/local/etc/apache24/extra/ 2>/dev/null
[manage@victor ~]$ sudo ls /usr/local/etc/apache24/Includes/ 2>/dev/null
[manage@victor ~]$ sudo find /usr/local/www/apache24/data -maxdepth 4 -type f 2>/dev/null | head -60
[manage@victor ~]$ sudo ls /usr/local/www/apache24/backup_data/ 2>/dev/null
[manage@victor ~]$ php -i 2>/dev/null | grep -iE 'expose_php|display_errors|allow_url_(include|fopen)|open_basedir|disable_functions'
allow_url_fopen => On => On
allow_url_include => Off => Off
disable_functions => no value => no value
display_errors => Off => Off
expose_php => On => On
open_basedir => no value => no value
[manage@victor ~]$ cat /usr/local/etc/php.ini 2>/dev/null | grep -vE '^\s*;|^\s*$' | head -60
[manage@victor ~]$ mysql -u root -e "SHOW DATABASES;" 2>/dev/null || echo '(root パス必要)'
(root パス必要)
[manage@victor ~]$ sudo ls /etc/mail/
Makefile  access.db	   domaintable	   helpfile	     mailertable     make	  sendmail.cf.bak  submit.cf	  submit.mc	 virtusertable
access	  aliasesdb-stamp  domaintable.db  local-host-names  mailertable.db  sendmail.cf  sendmail.mc	   submit.cf.bak  trusted-users  virtusertable.db
[manage@victor ~]$ sudo ls /usr/local/etc/courier-imap/ 2>/dev/null
[manage@victor ~]$ sudo grep -E '^[A-Z]' /etc/mail/sendmail.cf | head -30
V10/Berkeley
Cwlocalhost
Fw/etc/mail/local-host-names
CP.
DS
CO @ % !
C..
C[[
C{Accept}OK RELAY
C{ResOk}OKR
FR-o /etc/mail/relay-domains
Karith arith
Kmacro macro
C{Tls}VERIFY ENCR
Kdequote dequote
C{E}root
C{w}com6.local
DnMAILER-DAEMON
Kmailertable hash -o /etc/mail/mailertable.db
Kvirtuser hash -o /etc/mail/virtusertable.db
CPREDIRECT
Kaccess hash -T<TMPF> -o /etc/mail/access.db
DZ8.15.2
O SevenBitInput=False
O AliasWait=10
O AliasFile=/etc/aliases
O MinFreeBlocks=100
O BlankSub=.
O HoldExpensive=False
O DeliveryMode=background
[manage@victor ~]$ cat /etc/crontab
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed

[manage@victor ~]$ sudo ls /var/cron/tabs/ 2>/dev/null
[manage@victor ~]$ for u in $(sudo ls /var/cron/tabs/ 2>/dev/null); do
>   echo "--- crontab of $u ---"; sudo cat /var/cron/tabs/$u
> done
[manage@victor ~]$ ifconfig | grep -E 'inet |ether'
        inet 10.1.6.2  netmask 255.255.255.0  broadcast 10.1.6.255
        ether bc:24:11:a3:8a:70  txqueuelen 1000  (Ethernet)
        inet 127.0.0.1  netmask 255.0.0.0
[manage@victor ~]$ netstat -rn
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         10.1.6.254      0.0.0.0         UG        0 0          0 ens18
10.1.6.0        0.0.0.0         255.255.255.0   U         0 0          0 ens18
[manage@victor ~]$ cat /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
[manage@victor ~]$ cat /etc/resolv.conf
# Generated by NetworkManager
search com6.local
nameserver 10.1.6.1
[manage@victor ~]$ awk -F: '$3 >= 1000 || $1 == "root" {print $1":"$3":"$6":"$7}' /etc/passwd | head -40
root:0:/root:/bin/bash
nobody:65534:/:/sbin/nologin
aizawa:1001:/home/aizawa:/bin/bash
akagi:1002:/home/akagi:/bin/bash
arai:1003:/home/arai:/bin/bash
amano:1004:/home/amano:/bin/bash
amuro:1005:/home/amuro:/bin/bash
ishikawa:1006:/home/ishikawa:/bin/bash
ishibashi:1007:/home/ishibashi:/bin/bash
itou:1008:/home/itou:/bin/bash
ichihara:1009:/home/ichihara:/bin/bash
imamura:1010:/home/imamura:/bin/bash
irino:1011:/home/irino:/bin/bash
ueda:1012:/home/ueda:/bin/bash
utagawa:1013:/home/utagawa:/bin/bash
umino:1014:/home/umino:/bin/bash
etou:1015:/home/etou:/bin/bash
egawa:1016:/home/egawa:/bin/bash
okada:1017:/home/okada:/bin/bash
ogawa:1018:/home/ogawa:/bin/bash
ozeki:1019:/home/ozeki:/bin/bash
oda:1020:/home/oda:/bin/bash
onoda:1021:/home/onoda:/bin/bash
kai:1022:/home/kai:/bin/bash
kagawa:1023:/home/kagawa:/bin/bash
katakura:1024:/home/katakura:/bin/bash
kanemoto:1025:/home/kanemoto:/bin/bash
kamei:1026:/home/kamei:/bin/bash
karasawa:1027:/home/karasawa:/bin/bash
kawamura:1028:/home/kawamura:/bin/bash
kitajima:1029:/home/kitajima:/bin/bash
kimino:1030:/home/kimino:/bin/bash
kira:1031:/home/kira:/bin/bash
kindaichi:1032:/home/kindaichi:/bin/bash
kudou:1033:/home/kudou:/bin/bash
kumazawa:1034:/home/kumazawa:/bin/bash
kobayashi:1035:/home/kobayashi:/bin/bash
komiyama:1036:/home/komiyama:/bin/bash
sakai:1037:/home/sakai:/bin/bash
sakaguchi:1038:/home/sakaguchi:/bin/bash
[manage@victor ~]$ last -n 30 2>/dev/null
manage   pts/2        10.1.6.1         Fri Apr 24 11:28   still logged in
manage   pts/2        10.1.6.1         Fri Apr 24 11:28 - 11:28  (00:00)
manage   pts/4        10.1.16.12       Fri Apr 24 11:23 - 11:23  (00:00)
manage   pts/4        10.1.16.12       Fri Apr 24 11:22 - 11:22  (00:00)
manage   pts/2        10.1.16.15       Fri Apr 24 11:20 - 11:27  (00:07)
manage   pts/2        10.1.16.12       Fri Apr 24 11:19 - 11:19  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:14 - 11:14  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:14 - 11:14  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:12 - 11:12  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:11 - 11:11  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:03 - 11:03  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:03 - 11:03  (00:00)
manage   pts/2        10.1.16.12       Fri Apr 24 11:01 - 11:01  (00:00)
manage   pts/4        10.1.16.12       Fri Apr 24 10:50 - 10:55  (00:05)
manage   pts/4        10.1.16.12       Fri Apr 24 10:47 - 10:47  (00:00)
manage   pts/3        10.1.6.1         Fri Apr 24 10:39 - 11:28  (00:48)
manage   pts/3        10.1.16.16       Fri Apr 24 10:37 - 10:37  (00:00)
manage   pts/2        10.1.16.15       Fri Apr 24 10:33 - 10:58  (00:24)
manage   pts/2        10.1.16.12       Fri Apr 24 10:31 - 10:32  (00:00)
manage   pts/1        10.1.6.1         Fri Apr 24 09:56   still logged in
manage   pts/1        10.1.6.1         Fri Apr 24 09:51 - 09:54  (00:03)
manage   pts/0        10.1.16.16       Fri Apr 24 08:37   still logged in
manage   pts/0        10.1.16.16       Fri Apr 24 08:32 - 08:33  (00:00)
manage   pts/1        10.1.129.10      Fri Apr 24 01:43 - 04:00  (02:16)
obuchi   pts/0        10.1.129.10      Fri Apr 24 01:40 - 04:00  (02:19)
reboot   system boot  4.18.0-553.el8_1 Fri Apr 24 00:32   still running
root     tty1                          Thu Apr 23 19:07 - 19:07  (00:00)
reboot   system boot  4.18.0-553.el8_1 Thu Apr 23 18:10 - 19:07  (00:56)

wtmp は Wed Apr 15 16:07:01 2026 から始まっています
[manage@victor ~]$ w
 11:31:12 up 10:58,  3 users,  load average: 0.20, 0.10, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
manage   pts/0    10.1.16.16       08:37    2:00m  0.41s  0.41s -bash
manage   pts/1    10.1.6.1         09:56    1:30m  0.05s  0.05s -bash
manage   pts/2    10.1.6.1         11:28    0.00s  0.07s  0.00s w
[manage@victor ~]$ ls /usr/home/*/.history 2>/dev/null | head
[manage@victor ~]$ ls /home/*/.history 2>/dev/null | head
[manage@victor ~]$ sudo find / -perm -4000 -type f 2>/dev/null | head -40
/usr/bin/su
/usr/bin/umount
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/crontab
/usr/bin/sudo
/usr/bin/at
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/chsh
/usr/sbin/unix_chkpwd
/usr/sbin/grub2-set-bootflag
/usr/sbin/pam_timestamp_check
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/sssd/krb5_child
/usr/libexec/sssd/ldap_child
/usr/libexec/sssd/selinux_child
/usr/libexec/sssd/proxy_child
/usr/libexec/cockpit-session
[manage@victor ~]$ sudo find /usr/local/www /usr/local/etc /etc -type f -mtime -30 2>/dev/null | head -60
/etc/fstab
/etc/crypttab
/etc/dnf/modules.d/httpd.module
/etc/dnf/modules.d/nginx.module
/etc/dnf/modules.d/php.module
/etc/dnf/modules.d/mariadb.module
/etc/dnf/modules.d/perl.module
/etc/dnf/modules.d/perl-DBD-MySQL.module
/etc/dnf/modules.d/perl-DBI.module
/etc/dnf/modules.d/perl-IO-Socket-SSL.module
/etc/dnf/modules.d/perl-libwww-perl.module
/etc/dnf/modules.d/squid.module
/etc/dnf/plugins/kpatch.conf
/etc/dnf/plugins/copr.conf
/etc/dnf/plugins/debuginfo-install.conf
/etc/dnf/protected.d/dnf.conf
/etc/dnf/protected.d/setup.conf
/etc/dnf/protected.d/systemd.conf
/etc/dnf/protected.d/sudo.conf
/etc/dnf/protected.d/yum.conf
/etc/dnf/vars/contentdir
/etc/dnf/vars/rltype
/etc/dnf/vars/sigcontentdir
/etc/dnf/vars/stream
/etc/dnf/dnf.conf
/etc/libreport/events.d/collect_dnf.conf
/etc/libreport/events.d/mdadm_event.conf
/etc/logrotate.d/dnf
/etc/logrotate.d/samba
/etc/logrotate.d/sssd
/etc/logrotate.d/kvm_stat
/etc/logrotate.d/firewalld
/etc/logrotate.d/chrony
/etc/logrotate.d/psacct
/etc/logrotate.d/btmp
/etc/logrotate.d/wtmp
/etc/logrotate.d/httpd
/etc/logrotate.d/php-fpm
/etc/logrotate.d/mariadb
/etc/logrotate.d/syslog
/etc/logrotate.d/squid
/etc/logrotate.d/libreswan
/etc/pki/rpm-gpg/RPM-GPG-KEY-rockyofficial
/etc/pki/rpm-gpg/RPM-GPG-KEY-rockytesting
/etc/pki/ca-trust/extracted/edk2/README
/etc/pki/ca-trust/extracted/edk2/cacerts.bin
/etc/pki/ca-trust/extracted/java/README
/etc/pki/ca-trust/extracted/java/cacerts
/etc/pki/ca-trust/extracted/openssl/README
/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt
/etc/pki/ca-trust/extracted/pem/README
/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
/etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem
/etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem
/etc/pki/ca-trust/extracted/README
/etc/pki/ca-trust/source/README
/etc/pki/ca-trust/README
/etc/pki/ca-trust/ca-legacy.conf
/etc/pki/tls/certs/sendmail.pem
/etc/pki/tls/private/sendmail.key
[manage@victor ~]$ 

