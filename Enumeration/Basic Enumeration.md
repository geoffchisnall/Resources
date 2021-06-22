# **WORK IN PROGRESS**


## Network Enumeration

Some tools to check for live hosts and ports on a network.

### **netdiscover**
```bash
#:> sudo netdiscover -i eth0
```
### **fping**
```bash
#:> fping -a -g 192.168.1.0/24 2>/dev/null
```
### **NMAP**
```bash
ping scan
#:> sudo nmap -n -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}'

with --script=default and version detection and out put it to a file
#:> sudo nmap 192.168.1.0/2 -sC -sV -oN output.nmap
```
### **Rustscan**
```bash
normal scan
#:> rustscan -a 192.168.1.0/24 --ulimit 5000

With nmap with --script=default, version detection and output to a file
#:> rustscan -a 192.168.1.0/24 --ulimit 5000 -- -A -sC -sV -oN output.nmap
```
### **netcat**

You can also use netcat to check for open or closed ports
```bash
#:> nc -nv -u -z -w 1 192.168.1.1 161
```

## Web Enumeration

Basic web enumeration of various tools.

***This is still being updated to expand more options.***

### **Gobuster**

Gobuster by default uses:

**Wordlist** : none

**Threads** : 10

**User-Agent** : gobuster/3.1.0

**Recursion Depth** : none

**Status Codes** : 200, 204, 301, 302, 307, 308, 401, 403, 405

### **dir mode**

```bash
Normal scan
#:> gobuster dir -u http://192.168.1.1 -w wordlist

Extentions
#:> gobuster dir -u http://192.168.1.1 -w wordlist -x php,sql,bak

Disables TLS certificate validation
#:> gobuster dir -u http://192.168.1.1 -w wordlist -k

Status Codes
#:> gobuster dir -u http://192.168.1.1 -w wordlist -s 200,302

User Agent
#:> gobuster dir -u http://192.168.1.1 -w wordlist -a <User-Agent>

Use Proxy
#:> gobuster dir -u http://192.168.1.1 -w wordlist --proxy http://192.168.1.10:3128

Use Authentication
#:> gobuster dir -u http://192.168.1.1 -w wordlist -U user -P pass

Headers
#:> gobuster dir -u http://192.168.1.1 -w wordlist -H Accept:application/json -H "Authorization:Bearer {token}"
```
### **feroxbuster**

Feroxbuster by default uses:

**Wordlist** : raft-medium-directories.txt

**Threads** :  50

**User-Agent** : feroxbuster/2.2.1

**Recursion Depth** : 4

**Status Codes** : 200, 204, 301, 302, 307, 308, 401, 403, 405

```bash
Normal scan as per defaults
#:> feroxbuster --url http://192.168.1.1

Own Wordlist
#:> feroxbuster --url http://192.168.1.1 -w 'wordlist.txt'

Extentions php, sql, bak
#:> feroxbuster --url http://192.168.1.1 -x php,sql,bak

Recursion Depth
#:> feroxbuster --url http://192.168.1.1 -d 2

No Recusion Depth
#:> feroxbuster --url http://192.168.1.1 -n

Status codes
#:> feroxbuster --url http://192.168.1.1 -s 200,301

User Agent
#:> feroxbuster --url http://192.168.1.1 -a <USER_AGENT>

Headers
#:> feroxbuster --url http://192.168.1.1 -H Accept:application/json "Authorization:Bearer {token}"

Use Proxy
#:> feroxbuster --url http://192.168.1.1 -p http://192.168.1.10:3128
Disables TLS certificate validation

#:> feroxbuster --url http://192.168.1.1 -k
```
### **wfuzz**
wfuzz by default uses:

**Wordlist** : none

**Threads** :  10

**User-Agent** : Wfuzz/3.1.0

**Recursion Depth** : 4

**Status Codes** : 200, 204, 301, 302, 307, 308, 401, 403, 405

```bash
Normal scan
#:> wfuzz -z file,'wordlist' -u 192.168.1.1/FUZZ

Extentions
#:> wfuzz -z file,'wordlist' -z file,'extensions_common.txt' -u 192.168.1.1/FUZZ%FUZ2Z

User-Agent
#:> wfuzz -z file,'wordlist' -u 192.168.1.1/FUZZ -H "User-Agent: <USER-AGENT>"

Use Proxy
#:> wfuzz -z file,'wordlist' -u 192.168.1.1/FUZZ -p 192.168.1.10:3128:HTTP
```
### **ffuf**

```bash
Directory Fuzzing
#:> ffuf -w wordlist.txt:FUZZ -u http://192.168.1.1/FUZZ

Extension Fuzzing
#:> ffuf -w wordlist.txt:FUZZ -u http://192.168.1.1/indexFUZZ` 

Page Fuzzing
#:> ffuf -w wordlist.txt:FUZZ -u http://192.168.1.1/dir/FUZZ.php` 

Recursive Fuzzing
#:> ffuf -w wordlist.txt:FUZZ -u http://192.168.1.1/FUZZ -recursion -recursion-depth 1 -e .php -v`

Sub-domain Fuzzing
#:> ffuf -w wordlist.txt:FUZZ -u https://FUZZ.domain.com/` 

VHost Fuzzing
#:> ffuf -w wordlist.txt:FUZZ -u http://domain.com:PORT/ -H 'Host: FUZZ.domain.com' -fs xxx` 

Parameter Fuzzing - GET
#:> ffuf -w wordlist.txt:FUZZ -u http://sub.domain.com:PORT/admin/admin.php?FUZZ=key -fs xxx` 

Parameter Fuzzing - POST
#:> ffuf -w wordlist.txt:FUZZ -u http://sub.domain.com:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`
#:> ffuf -w ids.txt:FUZZ -u http://sub.domain.com:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`
```
### **dirb**
```bash
#:> dirb http://192.168.1.1 wordlist.txt
```
### **dirbuster**

This is a GUI version of dirb

## **SMB Enumeration**

### **Enumerate information from Windows and Samba systems**
```bash
#:> enum4linux -a 192.168.1.150
```
### **Show SMB shares**

```bash
#:> smbclient -U "user" -L 192.168.1.150
#:> showmount -e 192.16.1.150
```
### **Mount shares**

```bash
#:> sudo mount -t cifs //192.168.1.150/share$ smb/ -o user="user"
#:> smbclient \\\\192.168.1.150\\sharename -U guest
```

## SNMP Enumeration

### **SNMPWALK**
```bash
version 1 with public community string
#:> snmpwalk -v 1 -c public 192.168.1.10 .1

version 2 with public community string
#:> snmpwalk -v 2c -c public 192.168.1.10 .1
```

### **SNMP-CHECK**
```bash
version 1 with public community string
#:> snmp-check -v1 -c public 192.168.1.10 

version 2 with public community string
#:> snmp-check -v2c -c public 192.168.1.10

Detect write access to the SNMP
#:> snmp-check -v2c -c public 192.168.1.10 -w
```
