# 🕑 Late

![](../../.gitbook/assets/Late.png)

Link: [https://app.hackthebox.com/machines/463](https://app.hackthebox.com/machines/463)

### Nmap Scan

Let's start with enumeration with Nmap: `nmap -sS -A -sC -sV -T5 -oN scan.txt 10.129.132.140`

```
Nmap scan report for 10.129.132.140
Host is up (0.082s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
|_  256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   83.66 ms 10.10.14.1
2   83.65 ms 10.129.132.140
```

Port 22 & 80 are open. HTTP is hosted on `Port 80`

Let's visit that in our browser

### Port 80

![port 80](<../../.gitbook/assets/home page.png>)

By seeing the website there isn't that much.

I found one link in the source code

![source code](<../../.gitbook/assets/images htb source page.png>)

To visit that page, we have to add `images.late.htb`  to our `HOST`

![host](../../.gitbook/assets/host.png)

after editing `/etc/hosts` and adding our machine's IP we are good to do.

### images.late.htb

![](<../../.gitbook/assets/vuln webpage higlighted with flask.png>)

