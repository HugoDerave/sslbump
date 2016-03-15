SSLBump.sh
==========
What is SSLBump.sh?
------------------------------------------------
SSLBump.sh is a script that installs and configures Squid 3.5.15 in SSL Bump mode that is compatible
with SNI(peeks at certs in the first step), it also installs and configures a ICAP server for it which
is GreasySpoon 1.0.10 and installs scripts to log the request and response headers of users that are intercepted
by Squid.The script installs both Squid and Greasyspoon as daemons.

Where are the log files?
------------------------------------------------
All logs reside in /var/log/squid.

What distro is this script working on?
------------------------------------------------
Currently working and tested on Debian 8.3.

Note: Run this script at your own risk! For now it doesn't check for previous installations so i recommend you run it only once!