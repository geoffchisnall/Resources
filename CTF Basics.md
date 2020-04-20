#### first start off with NMAP scan
- `sudo nmap -sC -sV -oA testbox 10.0.0.1`

#### wfuzz webdirectory
- `wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt -u 10.0.0.1/FUZZ`
- `wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt -z file,/usr/share/wordlists/dirb/extensions_common.txt -u 10.0.0.1/FUZZ%FUZ2Z`
