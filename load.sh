#!/bin/bash
set -x
root=`pwd`

checkerror() {
	if [ "$?" != "0" ]; then
		exit 1
	fi
}

mkdir -p /quadstor/tmp
chmod 777 /quadstor/tmp

if [ -f /usr/bin/chcon ]; then
        sudo /usr/bin/chcon -t textrel_shlib_t /quadstor/lib/libtl* > /dev/null 2>&1
        sudo /usr/bin/chcon -v -R -t httpd_unconfined_script_exec_t /var/www/cgi-bin/*.cgi > /dev/null 2>&1
fi

#sudo /sbin/modprobe netconsole netconsole=@192.168.242.146/eth0,@192.168.242.136/00:0C:29:9F:A5:36
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.2/eth0,@10.0.13.8/00:1B:24:F4:4E:A7
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.7/eth0,@10.0.13.8/00:1B:24:F4:4E:A7
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.7/eth0,@10.0.13.6/00:15:17:60:EF:CC
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.4/eth1,@10.0.13.3/00:15:17:60:EF:CC
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.4/eth1,@10.0.13.7/00:15:17:60:E7:B4
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.4/eth1,@10.0.13.6/00:15:17:26:72:D6
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.7/br0,@10.0.13.4/00:15:17:26:70:D2
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.100/eth0,@10.0.13.4/00:15:17:26:70:D2
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.101/eth2,6667@10.0.13.4/00:15:17:26:70:D2
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.6/eth0,6667@10.0.13.4/00:15:17:26:70:D2
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.6/eth0,@10.0.13.4/00:15:17:26:70:D2
#sudo /sbin/modprobe netconsole netconsole=@10.0.13.7/eth0,@10.0.13.6/00:15:17:60:EF:CC
#sudo /sbin/modprobe netconsole netconsole=@192.168.1.34/eth0,@192.168.1.88/00:15:17:60:EF:CC
#sudo /bin/bash -c 'sudo echo 15 > /proc/sys/kernel/printk'
sync
sudo /quadstor/pgsql/etc/pgsql start

sudo /sbin/insmod /quadstor/quadstor/export/coredev.ko
checkerror

sudo /sbin/insmod /quadstor/quadstor/export/ldev.ko
checkerror

sudo /sbin/insmod /quadstor/quadstor/target-mode/iscsi/kernel/iscsit.ko

sleep 6

cd $root/masterd
sh load.sh

sudo /quadstor/quadstor/target-mode/iscsi/usr/ietd  -d 3 -c /quadstor/conf/iscsi.conf

cd $root/scctl
./scctl -l
cd $root
