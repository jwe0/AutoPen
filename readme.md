# Auto Pen
> *Automated python script for finding basic vulnerabilities in different protocols*

## Install
1. Download the zip or clone the repository
2. Navigate to the folder of Auto Pen
3. Run `pip install -r requirements.txt` to install the requirements
4. Run main.py and when prompted input your target
5. Let the script run through its checks

## Features
- Retrieve data from robots and license files
- Enumerate common login portals
- Supports a range of protocols
- Auto scans for CVE exploits

### Example
## HTTP
```
[#] Scanning... (This may take a while)

[#] Checking for web server...

[+] Web server detected WordPress.com: Build a Site, Sell Your Stuff, Start a Blog &amp; More
[1]      » http://wordpress.com:80/
[2]      » http://wordpress.com:443/
[+] Common files found
[1]      » /robots.txt
                 » # If you are regularly crawling WordPress.com sites, please use our firehose to receive real-time push updates instead.
                 » # Please see https://developer.wordpress.com/docs/firehose/ for more details.
                 » Sitemap: https://wordpress.com/sitemap.xml
                 » Sitemap: https://wordpress.com/news-sitemap.xml
                 » Sitemap: https://wordpress.com/go/sitemap.xml
                 » Sitemap: https://wordpress.com/blog/sitemap.xml
                 » Sitemap: https://wordpress.com/support/sitemap.xml
                 » User-agent: *
                 » Disallow: /wp-admin/
                 » Allow: /wp-admin/admin-ajax.php
                 » Disallow: /typo/
                 » Disallow: /read/
                 » Disallow: /*/read/
                 » Disallow: /log-in*?redirect_to=
                 » Disallow: /abuse/?*
                 » Disallow: /abuse?*
                 » Disallow: /plugins/?s=
                 » Disallow: /*/plugins/?s=
                 » Disallow: /*?aff=
                 » Disallow: /*&aff=
                 » Disallow: /*/?like_comment=
                 » Disallow: /wp-login.php
                 » Disallow: /wp-signup.php
                 » Disallow: /press-this.php
                 » Disallow: /remote-login.php
                 » Disallow: /activate/
                 » Disallow: /cgi-bin/
                 » Disallow: /mshots/v1/
                 » Disallow: /next/
                 » Disallow: /public.api/
                 » # This file was generated on Fri, 14 Jun 2024 20:01:26 +0000
[2]      » /sitemap.xml
[3]      » /sitemap.html
[+] Login portals found
[1]      » /wp-admin.html
[2]      » /login.html
[3]      » /admin.html
[+] Exploits found 1
[1]      » /vuln/detail/CVE-2023-50879
```
## FTP
```
[#] Scanning... (This may take a while)

[#] Checking for FTP server...

[+] FTP server detected 220-Welcome to test.rebex.net!
[+] Anonymous login possible
[1]      » pub
[2]      » readme.txt
```
## SSH
```
[#] Scanning... (This may take a while)

[#] Checking for SSH server...

[+] SSH server detected SSH-2.0-RebexSSH_5.0.8904.0
[+] Algorithms found
[1]      » Algorithms
                 » curve25519-sha256@libssh.org
                 » ecdh-sha2-nistp256
                 » ecdh-sha2-nistp384
                 » ecdh-sha2-nistp521
                 » diffie-hellman-group16-sha512
                 » diffie-hellman-group-exchange-sha256
                 » diffie-hellman-group14-sha256
                 » diffie-hellman-group-exchange-sha1
                 » diffie-hellman-group14-sha1
                 » diffie-hellman-group1-sha1
[2]      » Hexs
                 » aes128-ctr
                 » aes192-ctr
                 » aes256-ctr
                 » aes128-cbc
                 » aes192-cbc
                 » aes256-cbc
                 » 3des-cbc

```

## Footnote
Feel free to contribute to this project since you are probably much smarter than me.

###### Legal jargan
###### Don't use this for crimes :)