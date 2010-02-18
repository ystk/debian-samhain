/var/log/samhain/*.log {
	weekly
	missingok
	rotate 52
	compress
	delaycompress
	notifempty
	create 640 root adm
	sharedscripts
	postrotate
	   if [ -f /var/run/samhain/samhain.pid ]; then \
		/etc/init.d/samhain reload > /dev/null; fi
	endscript
}
