#!/bin/sh
set -x
sh buildinit.sh rhel5
rpmbuild -bb quadstorcore.spec && rpmbuild -bb quadstorclient.spec && rpmbuild -bb quadstoritf.spec && rpmbuild -bb quadstoritfmin.spec
