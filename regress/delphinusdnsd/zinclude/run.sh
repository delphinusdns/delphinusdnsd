#!/bin/ksh

#debug
#set -x

i=$1

dddctl configtest $i > /dev/null
if [ $? -eq 1 ]; then
	echo dddctl configtest failed! 1>&2
	exit 1
fi

(delphinusdnsd  -dvvv -l -f `pwd`/$i -s `pwd`/control.sock > output  2>&1 ) &

sleep 3
dddctl stop -s `pwd`/control.sock  >/dev/null 2>&1
sleep 3


#
# config4 checks if we can turn options to on... we zinclude so we should not
# see ^DNSSEC ENABLED
#

if [ XX$i == XX"config4" ]; then
	grep -q ^DNSSEC output

	if [ $? -ne 1 ]; then
		echo $i is not OK
		mv output output.bad
		exit 1
	fi

	echo $i is OK
	exit 0
fi

grep -q ^solarscale.de output
RETCODE=$?

if [ $RETCODE -eq 1 -a XX$i == XX"config1" ]; then
#
# This checks if we have solarscale.de inside out output we shouldn't
#
	echo $i is OK
elif [ $RETCODE -eq 1 -a XX$i == XX"config2" ]; then
#
# This checks if we have solarscale.de inside out output we shouldn't
#
	echo $i is OK
elif [ $RETCODE -eq 0 -a XX$i == XX"config3" ]; then
#
# This checks if we have solarscale.de inside out output we should
#
	echo $i is OK
else
	echo $i is not OK
	mv output output.bad
	exit 1
fi

exit 0
