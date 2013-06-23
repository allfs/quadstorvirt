#!/bin/bash
set -x 

root=`pwd`

sudo pkill ncdaemon
PIDOF="/sbin/pidof"
if [ ! -f /sbin/pidof ]; then
	PIDOF="/bin/pidof"
fi
while [ 1 ]; do
	ncdaemonpid=`$PIDOF ./ncdaemon 2> /dev/null`
	if [ "$ncdaemonpid" = "" ]; then
		break;
	fi
	sleep 2
done

cd $root/target-mode/iscsi
sh unloadiscsi.sh

cd $root
#/sbin/rmmod qla2xxx
/sbin/rmmod ldev 
/sbin/rmmod coredev 

sudo /sbin/rmmod netconsole
