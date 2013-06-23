#!/bin/bash
set -x
sudo pkill mdaemon
sudo rm -f /quadstor/.mdaemon
ulimit -c  unlimited
#valgrind --leak-check=yes --track-fds=yes --log-file=mdval.txt ./mdaemon
PATH="/sbin:/usr/sbin:/bin:/usr/bin:$PATH"
export PATH=$PATH
./mdaemon
