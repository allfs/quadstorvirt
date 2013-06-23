#!/bin/sh
set -x

sudo pkill ncdaemon
sleep 4

pkill ietd
rm -f /var/run/iet.sock
sleep 2

/sbin/kldunload iscsit
/sbin/kldunload ldev 
/sbin/kldunload coredev 
