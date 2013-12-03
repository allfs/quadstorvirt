%define quadstor_prereq  apache

Summary: QuadStor Storage Virtualization 
Name: quadstor-itf-minimal
Version: 3.0.54
Release: rhel5
Source0: %{name}-%{version}.tar.gz
License: None 
Group: DataStorage 
Vendor: QUADStor Systems 
URL: http://www.quadstor.com
Requires: kernel-devel, make, gcc, perl
Conflicts: quadstor-itf
BuildRoot: /var/tmp/%{name}-buildroot
%description
 QUADStor storage virtualization, data deduplication 
%build
cd /quadstor/quadstor/ && sh buildcluster.sh clean
exit 0

%install
rm -rf $RPM_BUILD_ROOT/

mkdir -p $RPM_BUILD_ROOT/etc/udev/rules.d
mkdir -p $RPM_BUILD_ROOT/quadstor/bin
mkdir -p $RPM_BUILD_ROOT/quadstor/src
mkdir -p $RPM_BUILD_ROOT/quadstor/src/export
cp /quadstor/quadstor/export/devq.[ch] $RPM_BUILD_ROOT/quadstor/src/export/
cp /quadstor/quadstor/export/ldev_linux.[ch] $RPM_BUILD_ROOT/quadstor/src/export/
cp /quadstor/quadstor/export/linuxdefs.h $RPM_BUILD_ROOT/quadstor/src/export/
cp /quadstor/quadstor/export/exportdefs.h $RPM_BUILD_ROOT/quadstor/src/export/
cp /quadstor/quadstor/export/missingdefs.h $RPM_BUILD_ROOT/quadstor/src/export/
cp /quadstor/quadstor/export/qsio_ccb.h $RPM_BUILD_ROOT/quadstor/src/export/
cp /quadstor/quadstor/export/core_linux.c $RPM_BUILD_ROOT/quadstor/src/export/
cp /quadstor/quadstor/export/Makefile.dist $RPM_BUILD_ROOT/quadstor/src/export/Makefile
cp /quadstor/quadstor/export/queue.h $RPM_BUILD_ROOT/quadstor/src/export/

mkdir -p $RPM_BUILD_ROOT/quadstor/src/common
cp /quadstor/quadstor/common/ioctldefs.h $RPM_BUILD_ROOT/quadstor/src/common/
cp /quadstor/quadstor/common/commondefs.h $RPM_BUILD_ROOT/quadstor/src/common/


install -m 755 /quadstor/quadstor/scripts/builditf.min.linux.sh $RPM_BUILD_ROOT/quadstor/bin/builditf.min
install -m 644 /quadstor/quadstor/scripts/quadstor-udev.rules $RPM_BUILD_ROOT/etc/udev/rules.d/65-quadstor.rules

%post
	echo "Minimal 3.0.54 for RHEL/CentOS 5.x" > /quadstor/etc/quadstor-itf-version
	echo "Building required kernel modules"
	echo "Running /quadstor/bin/builditf.min"
	sleep 5
	/quadstor/bin/builditf.min

%preun
	cmod=`/sbin/lsmod | grep coredev`
	if [ "$cmod" != "" ]; then
		if [ -f /etc/rc.d/init.d/quadstor ]; then
			/etc/rc.d/init.d/quadstor stop
		else
			/etc/rc.d/quadstor stop
		fi
	fi

	cmod=`/sbin/lsmod | grep coredev`
	if [ "$cmod" != "" ]; then
		echo "Unable to shutdown QUADStor service cleanly. Please restart the system and try again"
		exit 1
	fi

	exit 0

%postun
	rm -f /quadstor/etc/quadstor-itf-version
	for i in `ls -1d /quadstor/lib/modules/*`; do
		if [ -d $i ]; then
			rm -rf $i > /dev/null 2>&1
		fi
	done
	rmdir --ignore-fail-on-non-empty /quadstor/lib/modules > /dev/null 2>&1
	rmdir --ignore-fail-on-non-empty /quadstor/src > /dev/null 2>&1

%files
%defattr(-,root,root)
/quadstor/src/export/
/quadstor/src/common/
/quadstor/bin/builditf.min
/etc/udev/rules.d/65-quadstor.rules

%clean
rm -rf $RPM_BUILD_ROOT/
