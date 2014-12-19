Unwelcome is a Python tool for monitoring brute force SSH attempts and adding them
to a ipset to block in iptables. 

There are many other tools already that do similar things, this is mine. 

###IPTables example

The below example shows how to mix the unwelcome ipset and iptables built in rules for rate limitting 
to ward off pesky brute force attacks

```
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p all -m set  --match-set unwelcome src -j DROP
-A INPUT -p icmp -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -m state --state NEW -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -m recent --set --name SSH --mask 255.255.255.255 --rsource
-A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH --mask 255.255.255.255 --rsource -j DROP
-A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -m recent --update --seconds 3600 --hitcount 10 --rttl --name SSH --mask 255.255.255.255 --rsource -j DROP
-A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
```

###Required Packages
- python-sqlalchemy
- python-configparser
