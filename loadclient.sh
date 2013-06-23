#!/bin/bash
set -x
root=`pwd`

checkerror() {
	if [ "$?" != "0" ]; then
		exit 1
	fi
}

#sudo /sbin/modprobe netconsole netconsole=@192.168.242.146/eth0,@192.168.242.136/00:0C:29:9F:A5:36
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.2/eth0,@10.0.13.8/00:1B:24:F4:4E:A7
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.7/eth0,@10.0.13.8/00:1B:24:F4:4E:A7
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.7/eth0,@10.0.13.6/00:15:17:60:EF:CC
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.4/eth1,@10.0.13.3/00:15:17:60:EF:CC
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.4/eth1,@10.0.13.7/00:15:17:60:E7:B4
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.4/eth1,@10.0.13.6/00:15:17:26:72:D6
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.7/br0,@10.0.13.4/00:15:17:26:70:D2
sudo /sbin/modprobe netconsole netconsole=@10.0.13.101/eth2,6667@10.0.13.4/00:15:17:26:70:D2
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.7/eth0,@10.0.13.6/00:15:17:60:EF:CC
#sudo /sbin/modprobe netconsole netconsole=@192.168.1.34/eth0,@192.168.1.88/00:15:17:60:EF:CC
#sudo /bin/bash -c 'sudo echo 15 > /proc/sys/kernel/printk'
sync
sudo /sbin/insmod /quadstor/quadstor/export/coredev.ko
checkerror

sudo /sbin/insmod /quadstor/quadstor/export/ldev.ko
checkerror

sleep 6

cd $root/target-mode/iscsi
sh loadiscsi.sh

sudo pkill ncdaemon
ulimit -c unlimited
cd /quadstor/quadstor/masterd && ln -fs mdaemon ncdaemon && sudo ./ncdaemon 

sleep 1

cd $root
