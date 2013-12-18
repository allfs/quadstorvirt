%define libvers 3.0.57
Summary: QuadStor Storage Virtualization 
Name: quadstor-client
Version: 3.0.57
Release: rhel5
Source0: %{name}-%{version}.tar.gz
License: None 
Group: DataStorage 
Vendor: QUADStor Systems 
URL: http://www.quadstor.com
Requires: coreutils, sg3_utils, e2fsprogs-libs
Conflicts: quadstor-core
BuildRoot: /var/tmp/%{name}-buildroot
Provides: libtlclnt.so()(64bit) libtlmsg.so()(64bit) libtlsrv.so()(64bit)
%description
 QUADStor storage virtualization, data deduplication 
%build
cd /quadstor/quadstor/ && sh buildcluster.sh clean
cd /quadstor/quadstor/ && sh buildcluster.sh

%install
rm -rf $RPM_BUILD_ROOT/

mkdir -p $RPM_BUILD_ROOT/quadstor/bin
mkdir -p $RPM_BUILD_ROOT/quadstor/sbin
mkdir -p $RPM_BUILD_ROOT/quadstor/lib
mkdir -p $RPM_BUILD_ROOT/quadstor/lib/modules
mkdir -p $RPM_BUILD_ROOT/quadstor/etc
mkdir -p $RPM_BUILD_ROOT/quadstor/etc/iet
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d

install -m 755 /quadstor/quadstor/masterd/mdaemon $RPM_BUILD_ROOT/quadstor/sbin/ncdaemon
install -m 755 /quadstor/quadstor/scctl/ndconfig $RPM_BUILD_ROOT/quadstor/bin/ndconfig
install -m 755 /quadstor/quadstor/scctl/rundiag $RPM_BUILD_ROOT/quadstor/bin/rundiag
install -m 755 /quadstor/quadstor/scctl/qmapping $RPM_BUILD_ROOT/quadstor/bin/qmapping
install -m 755  /quadstor/quadstor/library/client/libtlclnt.so $RPM_BUILD_ROOT/quadstor/lib/libtlclnt.so.%{libvers}
install -m 755 /quadstor/quadstor/library/server/libtlsrv.so $RPM_BUILD_ROOT/quadstor/lib/libtlsrv.so.%{libvers}
install -m 755 /quadstor/quadstor/library/common/libtlmsg.so $RPM_BUILD_ROOT/quadstor/lib/libtlmsg.so.%{libvers}
install -m 644 /quadstor/quadstor/lib/modules/corelib.o $RPM_BUILD_ROOT/quadstor/lib/modules/
install -m 744 /quadstor/quadstor/etc/quadstor.linux.client $RPM_BUILD_ROOT/etc/rc.d/init.d/quadstor
install -m 755 /quadstor/quadstor/scripts/diaghelper.linux $RPM_BUILD_ROOT/quadstor/bin/diaghelper
install -m 444 /quadstor/quadstor/LICENSE $RPM_BUILD_ROOT/quadstor/
install -m 444 /quadstor/quadstor/GPLv2 $RPM_BUILD_ROOT/quadstor/

#Install src
mkdir -p $RPM_BUILD_ROOT/quadstor/src/others
cp /quadstor/quadstor/core/sha*.[ch] $RPM_BUILD_ROOT/quadstor/src/others/
cp /quadstor/quadstor/core/sha*.s $RPM_BUILD_ROOT/quadstor/src/others/
cp /quadstor/quadstor/core/md32_common.h $RPM_BUILD_ROOT/quadstor/src/others/
cp /quadstor/quadstor/library/server/md5*.[ch] $RPM_BUILD_ROOT/quadstor/src/others/
cp /quadstor/quadstor/core/lzf*.[ch] $RPM_BUILD_ROOT/quadstor/src/others/
cp /quadstor/quadstor/core/lz4*.[ch] $RPM_BUILD_ROOT/quadstor/src/others/
cp /quadstor/quadstor/core/sysdefs/*.h $RPM_BUILD_ROOT/quadstor/src/others/


cd $RPM_BUILD_ROOT/quadstor/lib && ln -fs libtlclnt.so.%{libvers} libtlclnt.so.1
cd $RPM_BUILD_ROOT/quadstor/lib && ln -fs libtlclnt.so.%{libvers} libtlclnt.so
cd $RPM_BUILD_ROOT/quadstor/lib && ln -fs libtlsrv.so.%{libvers} libtlsrv.so.1
cd $RPM_BUILD_ROOT/quadstor/lib && ln -fs libtlsrv.so.%{libvers} libtlsrv.so
cd $RPM_BUILD_ROOT/quadstor/lib && ln -fs libtlmsg.so.%{libvers} libtlmsg.so.1
cd $RPM_BUILD_ROOT/quadstor/lib && ln -fs libtlmsg.so.%{libvers} libtlmsg.so

%post
	cat /quadstor/LICENSE
	echo ""
	echo "Performing post install. Please wait..."
	sleep 4

	/sbin/chkconfig --add quadstor

	exit 0

%preun
	/sbin/chkconfig --del quadstor

	cmod=`/sbin/lsmod | grep coredev`
	if [ "$cmod" != "" ]; then
		/etc/rc.d/init.d/quadstor stop
	fi

	cmod=`/sbin/lsmod | grep coredev`
	if [ "$cmod" != "" ]; then
		echo "Unable to shutdown QUADStor service cleanly. Please restart the system and try again"
		exit 1
	fi


%postun
	rm -rf /quadstor/sbin /quadstor/share /quadstor/src/others/
	rmdir --ignore-fail-on-non-empty /quadstor/lib > /dev/null 2>&1
	rmdir --ignore-fail-on-non-empty /quadstor/bin > /dev/null 2>&1
	rmdir --ignore-fail-on-non-empty /quadstor/etc > /dev/null 2>&1
	exit 0

%files
%defattr(-,root,root)
/quadstor/sbin/ncdaemon
/quadstor/bin/ndconfig
/quadstor/bin/rundiag
/quadstor/bin/qmapping
/quadstor/lib/libtlclnt.so.1
/quadstor/lib/libtlclnt.so.%{libvers}
/quadstor/lib/libtlclnt.so
/quadstor/lib/libtlsrv.so
/quadstor/lib/libtlsrv.so.1
/quadstor/lib/libtlsrv.so.%{libvers}
/quadstor/lib/libtlmsg.so
/quadstor/lib/libtlmsg.so.1
/quadstor/lib/libtlmsg.so.%{libvers}
/quadstor/lib/modules/corelib.o
/etc/rc.d/init.d/quadstor
/quadstor/bin/diaghelper

#src files
/quadstor/src/

#License
/quadstor/LICENSE
/quadstor/GPLv2

%clean
rm -rf $RPM_BUILD_ROOT/


