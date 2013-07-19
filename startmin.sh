#!/bin/sh

set -x
checkerror() {
	if [ "$?" != "0" ]; then
		exit 1
	fi
}

sync
sleep 4
/quadstor/pgsql/etc/pgsql start
checkerror
sleep 8
sudo /sbin/kldload /quadstor/quadstor/export/coredev.ko
checkerror

sudo /sbin/kldload /quadstor/quadstor/export/ldev.ko
checkerror

sleep 4
cd /quadstor/quadstor/masterd && sh load.sh
sleep 4

cd /quadstor/quadstor/scctl
./scctl -l
