#!/bin/sh
if [ ! -f /quadstor/etc/iet/targets.allow ]; then
	cp /quadstor/etc/iet/targets.allow.sample /quadstor/etc/iet/targets.allow
fi

if [ ! -f /quadstor/etc/iet/initiators.allow ]; then
	cp /quadstor/etc/iet/initiators.allow.sample /quadstor/etc/iet/initiators.allow
fi

if [ ! -f /quadstor/etc/iet/ietd.conf ]; then
	cp /quadstor/etc/iet/ietd.conf.sample /quadstor/etc/iet/ietd.conf
fi

echo "3.0.50 for FreeBSD 8.2" > /quadstor/etc/quadstor-itf-version
exit 0
