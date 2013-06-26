#!/bin/sh
set -x 
for i in `ls -1`; do
	sed -i -e "s/3.0.39/3.0.39/g" $i
	sed -i -e "s/3.0.39-x86_64/3.0.39-x86_64/g" $i
done
