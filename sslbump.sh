#/bin/bash

###########################################################################
#
#    Script that configures and installs Squid with SSL Bump
#    Copyright (C) 2016 Daniel Smilevski
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/
#
###########################################################################

echo "Checking if you are root..."

if [ "$(whoami)" != "root" ]
then
	echo "Need root privileges to run this script."
	exit 1
else
	echo "You are root, perfect!"
fi

echo "Checking for internet connection..."

if [ "$(ping -c 1 8.8.8.8 | grep 'bytes from')" == "" ] 
then
	echo "You need to be connected to the internet to run this script."
	exit 1
else
	echo "Internet found, ok!"
fi

printf "Select temp dir to install programs in[default:/tmp/squid]:"
read TMPDIR

if [ "$TMPDIR" == "" ]
then
	TMPDIR=/tmp/squid
fi

if [ ! -d "$TMPDIR" ]
then
	mkdir -p $TMPDIR
fi

printf "Select dir to install greasyspoon in[default:$GREASYDIR]:"
read GREASYDIR

if [ "$GREASYDIR" == "" ]
then
       GREASYDIR=/opt/greasyspoon
fi

if [ ! -d "$GREASYDIR" ]
then
        mkdir -p "$GREASYDIR"
fi

echo "Checking for Squid dependencies..."

if [ "$(dpkg --list | grep 'g++')" != "" ]
then
        echo "G++ compiler present."
else
	echo "Installing G++..."
	apt-get -y install g++
fi

if [ "$(dpkg --list | grep 'gcc')" != "" ]
then
        echo "GCC compiler present."
else
        echo "Installing GCC..."
        apt-get -y install gcc
fi

if [ "$(dpkg --list | grep 'make')" != "" ]
then
        echo "Make present."
else
        echo "Installing make..."
        apt-get -y install make
fi

if [ "$(dpkg --list | grep 'libssl-dev')" != "" ]
then
        echo "SSL library present."
else
        echo "Installing SSL library..."
        apt-get -y install libssl-dev
fi


echo "Fetching squid source from the internet and unpacking data..."
cd $TMPDIR
wget http://www.squid-cache.org/Versions/v3/3.5/squid-3.5.15.tar.gz -O - | tar -xzv

echo "Configuring Squid with enabled SSL and ICAP..."

sh $TMPDIR/squid-3.5.15/configure --prefix=/usr --localstatedir=/var --libexecdir=/lib/squid --datadir=/usr/share/squid --sysconfdir=/etc/squid --with-logdir=/var/log/squid --with-pidfile=/var/run/squid.pid --enable-icap-client --enable-linux-netfilter --enable-ssl-crtd --with-openssl --enable-ltdl-convenience

echo "Making Squid..."

make

echo "Installing Squid..."

make install

echo "Creating self-signed certificate for Squid..."

mkdir /etc/squid/ssl_cert
cd /etc/squid/ssl_cert
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj "/C=MK/ST=Macedonia/L=Skopje/O=SSSLBump Co./CN=www.proxy.mk" -keyout squid.key  -out squid.crt
chown -R proxy:proxy .
chmod -R 700 .


echo "Creating log directory for Squid..."
mkdir /var/log/squid
chown -R proxy:proxy /var/log/squid

echo "Calling Squid to create swap directories and initialize cert cache dir..."
squid -z
if [ -d "/var/cache/squid/ssl_db" ]
then
	rm -rf /var/cache/squid/ssl_db
fi
/lib/squid/ssl_crtd -c -s /var/cache/squid/ssl_db
chown -R proxy:proxy /var/cache/squid/ssl_db

echo "Creating Squid conf file..."

cat << EOF > /etc/squid/squid.conf
#
# Recommended minimum configuration:
#

# Example rule allowing access from your local networks.
# Adapt to list your (internal) IP networks from where browsing
# should be allowed
acl localnet src 10.0.0.0/8     # RFC1918 possible internal network
acl localnet src 172.16.0.0/12  # RFC1918 possible internal network
acl localnet src 192.168.0.0/16 # RFC1918 possible internal network
acl localnet src fc00::/7       # RFC 4193 local private network range
acl localnet src fe80::/10      # RFC 4291 link-local (directly plugged) machines

acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT

#
# Recommended minimum Access Permission configuration:
#
# Deny requests to certain unsafe ports
http_access deny !Safe_ports

# Deny CONNECT to other than secure SSL ports
http_access deny CONNECT !SSL_ports

# Only allow cachemgr access from localhost
http_access allow localhost manager
http_access deny manager

# We strongly recommend the following be uncommented to protect innocent
# web applications running on the proxy server who think the only
# one who can access services on "localhost" is a local user
#http_access deny to_localhost

#
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS
#

# Example rule allowing access from your local networks.
# Adapt localnet in the ACL section to list your (internal) IP networks
# from where browsing should be allowed
http_access allow localnet
http_access allow localhost

# And finally deny all other access to this proxy
http_access deny all

# Squid normally listens to port 3128

http_port 3130
http_port 3128 intercept
https_port 3129 intercept ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/ssl_cert/squid.crt key=/etc/squid/ssl_cert/squid.key
#always_direct allow all
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all
#sslproxy_cert_error deny all

# Uncomment and adjust the following to add a disk cache directory.
#cache_dir ufs /usr/local/squid/var/cache/squid 100 16 256

# Leave coredumps in the first cache dir
coredump_dir /var/cache/squid

# Change logging directory to /var/log
cache_effective_user proxy
cache_log /var/log/squid/cache.log
access_log /var/log/squid/access.log

#
# Add any of your own refresh_pattern entries above these.
#
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320


# Add sslcrtd config incase server is used in a busy environment this will be bumped

sslcrtd_program /lib/squid/ssl_crtd -s /var/cache/squid/ssl_db -M 4MB
sslcrtd_children 5

# Add ICAP and hope for the best

icap_enable on

icap_send_client_ip on

icap_service service_req reqmod_precache bypass=1 icap://127.0.0.1:1344/request
adaptation_access service_req allow all

icap_service service_resp respmod_precache bypass=0 icap://127.0.0.1:1344/response
adaptation_access service_resp allow all
EOF

echo "Fetching greasyspoon from the internet..."
cd $TMPDIR
wget http://netcologne.dl.sourceforge.net/project/greasyspoon/greasyspoon-release-1.0.10.tar.gz -O - | tar -xzv

echo "Checking for greasyspoon dependencies..."

if [ "$(dpkg --list | grep 'jre')" != "" ]
then
        echo "JRE present."
else
        echo "Installing default jre..."
        apt-get -y install default-jre
fi

if [ "$(dpkg --list | grep 'jdk')" != "" ]
then
        echo "JDK present."
else
        echo "Installing default jdk..."
        apt-get -y install default-jdk
fi

echo "Copying greasyspoon to directory..."
cp -R $TMPDIR/greasyspoon-release-1.0.10/* $GREASYDIR/

echo "Adding logging scripts to greasyspoon..."

cat << EOF > $GREASYDIR/serverscripts/LogRequests.req.server.java
#rights=ADMIN
//-------------------------------------------------------------------
// ==ServerScript==
// @name            LogRequests
// @status on
// @description    Logs HTTP responses, written by Daniel Smilevski(http://github.com/dani87)
// @include        .*
// @exclude
// ==/ServerScript==
// --------------------------------------------------------------------
// Note: use httpMessage object methods to manipulate HTTP Message
// use debug(String s) method to trace items in service log (with log level >=FINE)
// ---------------

// ---------------
 import java.io.*;

 public void main(HttpMessage httpMessage){
     try
         {
             String logfile = "/var/log/squid/request-http.log";
             FileWriter fw = new FileWriter(logfile,true);
             fw.write("IP:" + httpMessage.getUsername() + "\n\n");
             fw.write("Request:\n");
             fw.write(httpMessage.getRequestHeaders() + "\n\n");
             fw.close();
         }
    catch(IOException ioe)
        {
            System.err.println("IOException: " + ioe.getMessage());
        }

}
EOF

cat << EOF > $GREASYDIR/serverscripts/LogResponses.req.server.java
#rights=ADMIN
//-------------------------------------------------------------------
// ==ServerScript==
// @name            LogResponses
// @status on
// @description    Logs HTTP responses, written by Daniel Smilevski(http://github.com/dani87)
// @include        .*
// @exclude
// @responsecode    200 301 302
// ==/ServerScript==
// --------------------------------------------------------------------
// Note: use httpMessage object methods to manipulate HTTP Message
// use debug(String s) method to trace items in service log (with log level >=FINE)
// ---------------

// ---------------
 import java.io.*;

 public void main(HttpMessage httpMessage){
     try
         {
             String logfile = "/var/log/squid/response-http.log";
             FileWriter fw = new FileWriter(logfile,true);
             fw.write("IP:" + httpMessage.getUsername() + "\n\n");
             fw.write("Request:\n");
             fw.write(httpMessage.getRequestHeaders() + "\n\n");
             fw.write("Response:\n");
             fw.write(httpMessage.getResponseHeaders() + "\n\n");
             fw.close();
         }
    catch(IOException ioe)
        {
            System.err.println("IOException: " + ioe.getMessage());
        }

}
EOF

echo "Creating greasyspoon daemon..."

JAVA_HOMEDIR=$(readlink -nf $(which java) | xargs dirname | xargs dirname | xargs dirname)

cp $TMPDIR/greasyspoon-release-1.0.10/greasyspoon /etc/init.d/greasyspoon

sed "s~JAVA_HOME=.*~JAVA_HOME="$JAVA_HOMEDIR"~g" -i /etc/init.d/greasyspoon
sed "s~GS_HOME=.*~GS_HOME="$GREASYDIR"~g" -i /etc/init.d/greasyspoon
sed "s~daemon=.*~daemon=\"true\"~g" -i /etc/init.d/greasyspoon
sed -i -e "1d" /etc/init.d/greasyspoon
sed "s~#\!/bin/sh~#\!/bin/sh\n~g" -i /etc/init.d/greasyspoon
chmod 755 /etc/init.d/greasyspoon

lvl=$(runlevel | sed 's/[^0-9]//g')
ln -s /etc/init.d/greasyspoon /etc/rc$lvl.d/S03greasyspoon

echo "Creating Squid daemon..."

cp $TMPDIR/squid-3.5.15/tools/sysvinit/squid.rc /etc/init.d/squid
chmod 755 /etc/init.d/squid
ln -s /etc/init.d/squid /etc/rc$lvl.d/S02squid

echo "Installation finished."
echo "Cleaning up temp dir..."

rm -rf $TMPDIR

echo -n "Do you want to reboot (y/n)? "
read answer
if echo "$answer" | grep -iq "^y" ;then
    reboot now
fi

