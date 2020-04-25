# Basic Enumeration at the start
#### NMAP Scan
- `sudo nmap -sC -sV -oA testbox 10.0.0.1`

### Web Directory Enumeration
#### gobuster
- `gobuster dir -u http://10.0.0.1 -w /usr/share/wordlists/dirb/big.txt`

#### wfuzz
directory  
- `wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 -u 10.0.0.1/FUZZ`  
filename + extension  
- `wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt -z file,/usr/share/wordlists/dirb/extensions_common.txt --hc 404 -u 10.0.0.1/FUZZ%FUZ2Z`  
deeper enumeration  
- `wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt -z file,/usr/share/wordlists/dirb/big.txt -z file,/usr/share/wordlists/dirb/extensions_common.txt --hc 404 -u 10.0.0.1/FUZZ/FU2Z%FUZ3Z`

### SMB Enumeration

- `enum4linux -a 10.0.0.1`
- `smbclient -U "user" -L 10.0.0.1`
- `showmount -e 10.0.0.1`
- `sudo mount -t cifs //10.0.0.1/share$ smb/ -o user="user"`

### LDAP Enumeration

- `jxplorer`




