#!/bin/sh

if [ -d /usr/local/www/apache22/ ]; then
	htdocs=/usr/local/www/apache22/data;
	cgibin=/usr/local/www/apache22/cgi-bin;
elif [ -d /usr/local/www/ ]; then
	htdocs=/usr/local/www/data;
	cgibin=/usr/local/www/cgi-bin;
else
	htdocs=/var/www/html
	cgibin=/var/www/cgi-bin
fi

if [ -d /quadstorvtl/httpd/cgi-bin ]; then
	cgilist=`cd /quadstor/httpd/cgi-bin && ls -1 *.cgi`
	for i in $cgilist; do
		rm -f $cgibin/$i
	done
fi

rm -rf $htdocs/quadstor

cmp=`cmp -s /quadstor/httpd/www/index.html $htdocs/index.html`
if [ "$?" = "0" ]; then
	rm -f $htdocs/index.html
fi

cmod=`/sbin/kldstat | grep coredev`
if [ "$cmod" = "" ]; then
	return
fi


/etc/rc.d/quadstor stop > /dev/null 2>&1
cmod=`/sbin/kldstat | grep coredev`
if [ "$cmod" = "" ]; then
	return
fi

/etc/rc.d/quadstor onestop > /dev/null 2>&1
cmod=`/sbin/kldstat | grep coredev`
if [ "$cmod" = "" ]; then
	return
fi

echo "Unable to shutdown QUADStor service cleanly. Please restart the system and try again"
exit 1
