#!/bin/sh
set -x
sh buildinit.sh sles11
rpmbuild -bb quadstorcoresles.spec && rpmbuild -bb quadstorclientsles.spec && rpmbuild -bb quadstoritfsles.spec && rpmbuild -bb quadstoritfminsles.spec
