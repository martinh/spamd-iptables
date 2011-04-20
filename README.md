## A port of OpenBSD spamd to Linux iptables

This is a port of the OpenBSD spam deferral daemon [spamd](http://www.openbsd.org/spamd/ "spamd") to Linux and iptables.

### Setup

1. Make and install

		$ make
		# make install

2. Install config files

		# mkdir /etc/obspamd
		# echo "@example.com" > /etc/obspamd/alloweddomains
		# cp etc/obspamd.conf.sample /etc/obspamd/obspamd.conf
		# $EDITOR /etc/obspamd/obspamd.conf

3. Setup cron

	Configure cron to run `/usr/local/sbin/obspamd-setup` once every few
	hours to setup any blacklists you've configured in `obspamd.conf`.

4. Install required service entries

	`obspamd` uses `getservbyname` to find what ports to use:

		# cat etc/services >> /etc/services

5. Redirect iptables logs to `obspamlogd`

	Make iptables log all SMTP connections so `obspamlogd` can update its database:

		# iptables -A INPUT -p tcp -m tcp --dport 25 --tcp-flags FIN,SYN,RST,ACK SYN -j LOG --log-prefix "obspamlogd: "
		# iptables -A OUTPUT -p tcp -m tcp --dport 25 --tcp-flags FIN,SYN,RST,ACK SYN -j LOG --log-prefix "obspamlogd: "

	`obspamlogd` reads the above iptables kernel logs via a pipe. If you're using rsyslog,
	there is a sample config file you can use:

		# cp etc/rsyslog.conf /etc/rsyslog.d/obspamlogd.conf

6. Setup iptables

	Create a chain in the nat table where whitelisted connections are placed:

		# iptables -t nat -N spamd-white

	Setup iptables to redirect incoming connections to `obspamd`:

		# iptables -t nat -A PREROUTING -p tcp -m tcp --dport 25 -j spamd-white
		# iptables -t nat -A PREROUTING -p tcp -m tcp --dport 25 -j REDIRECT --to-ports 8025
		# iptables -t nat -A spamd-white -j RETURN

	You also need to accept whitelisted connections to port 25 and 8025 (the `obspamd` port):

		# iptables -A INPUT -p tcp -m tcp --dport 8025 -j ACCEPT
		# iptables -A INPUT -p tcp -m tcp --dport 25 -j ACCEPT


## License

OpenBSD spamd uses the ISC and BSD licenses. See each individual file for details.

