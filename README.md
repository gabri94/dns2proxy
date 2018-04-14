dns2proxy  
=========  

Offensive DNS server  

This tools offer a different features for post-explotation once you change the DNS server to a Victim.
<Referer to help (-h) to new params options>

Feature 3  
---------  

Automatically the dns server detects and correct the changes thats my sslstrip+ do to the hostnames to avoid HSTS, so will response properly.
In this fork we try to use IDN Homographic symbols with cyrilic alphabet to deceive the user.

This server is necesary to make our fork of sslstrip2

>root@kali:~/dns2proxy# nslookup webaccounts.google.com 127.0.0.1    <-- DNS response like accounts.google.com  
>Server:         127.0.0.1  
>Address:        127.0.0.1#53  
>  
>Name:   webaccounts.google.com  
>Address: 172.16.48.128  
>Name:   webaccounts.google.com  
>Address: 172.16.48.230  
>Name:   webaccounts.google.com  
>Address: 74.125.200.84  
>  
>root@kali:~/dns2proxy# nslookup wwww.yahoo.com 127.0.0.1            <-- Take care of the 4 w! DNS response like  
>Server:         127.0.0.1                                                     www.yahoo.com  
>Address:        127.0.0.1#53  
>  
>Name:   wwww.yahoo.com  
>Address: 172.16.48.128  
>Name:   wwww.yahoo.com  
>Address: 172.16.48.230  
>Name:   wwww.yahoo.com  
>Address: 68.142.243.179  
>Name:   wwww.yahoo.com  
>Address: 68.180.206.184  


Instalation  
-----------  

dnspython (www.dnspython.com) is needed.
Tested with Python 2.6 and Python 2.7.


Config files description
------------------------
resolv.conf: DNS server to forward the queries.
>Ex:
>nameserver 8.8.8.8
