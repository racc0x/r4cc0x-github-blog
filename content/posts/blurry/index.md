---
title: HTB - Blurry
description: HTB - Blurry
publishDate: 2024-02-02
tags:
  - HackTheBox
  - CVE-2024-24590
  - ClearML
  - pickle-files
  - pth-files
  - artifact
  - API
---

## Box Info

| Name                  | Blurry           | 
| :-------------------- | ---------------: |
| Release Date          | 30 Mar, 2024     |
| OS                    | Linux            |
| Rated Difficulty      | Medium           |

## **Enumeration**

```bash
nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.11.19 -oG allports
nmap -sCV -p 22,80 10.10.11.19 -oN targeted
```

![Image](0.png)

```bash
echo " 10.10.11.19 app.blurry.htb" | sudo tee -a /etc/hosts
```

## ClearML

![Image](1.png)

At this point, it is important to know what clear ML is and how it works.
After much searching and gathering information, I found that we can connect through a Python package called clearml-agent and create an environment.

During the research process, I found that clearml has a **`CVE-2024-24590: Pickle Load on Artifact Get`**.

## CVE-2024-24590

*ClearML involves the inherent insecurity of pickle files. We discovered that an attacker could create a pickle file containing arbitrary code and upload it as an artifact to a project via the API. When a user calls the get method within the Artifact class to download and load a file into memory, the pickle file is deserialized on their system, running any arbitrary code it contains.*

<https://hiddenlayer.com/research/not-so-clear-how-mlops-solutions-can-muddy-the-waters-of-your-supply-chain/#The-Vulns>

![Image](3.png)

### Create credentials

To do this, we need to create new credentials to connect through clearml-agent, and to set up, we use the 'init' option.

![Image](4.png)

We press enter on the options and boom, we're connected.

![Image](5.png)

So once connected, we'll proceed to exploit the vulnerability.

![Image](6.png)

<https://clear.ml/docs/latest/docs/guides/reporting/using_artifacts/

<https://davidhamann.de/2020/04/05/exploiting-python-pickle/>

![Image](7.png)

## Privilege Escalation
### Sudo -l
Once **I had the reverse shell**, I continued with my enumeration and found a vulnerability with 'sudo -l

![Image](2.png)

I dug into the files and found that when executing /usr/bin/`evaluate_model`, it ran the `demo_model.pth`, which in turn executed the .py file located in `/models/`{: .filepath}. So, I modified the .py file to obtain a reverse shell.

![Image](8.png)

<https://www.revshells.com/>

But be careful, it runs with 'sudo' as it doesn't require a password to execute it, so we'll obtain a privileged reverse shell.

```bash
sudo evaluate_model /models/demo_model.pth
```

![Image](9.png)

With netcat listening the port 9001

![Image](10.png)

**`Root`**

![Image](11.png)
