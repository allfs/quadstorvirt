#!/bin/sh

set -x
checkerror() {
	if [ "$?" != "0" ]; then
		exit 1
	fi
}

sync
sudo /sbin/kldload /quadstor/quadstor/export/coredev.ko
checkerror

sudo /sbin/kldload /quadstor/quadstor/export/ldev.ko
checkerror

/sbin/kldload /quadstor/quadstor/target-mode/iscsi/kernel/iscsit.ko
checkerror

/quadstor/quadstor/target-mode/iscsi/usr/ietd -d 3 -c /quadstor/conf/iscsi.conf
checkerror

sleep 4
sudo pkill ncdaemon
ulimit -c unlimited
cd /quadstor/quadstor/masterd && ln -f mdaemon ncdaemon && sudo /quadstor/quadstor/masterd/ncdaemon 
sleep 4

