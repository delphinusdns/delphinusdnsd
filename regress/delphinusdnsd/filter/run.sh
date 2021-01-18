#!/bin/ksh

#set -x

i=$1

dddctl configtest $i > /dev/null
if [ $? -eq 1 ]; then
	echo dddctl configtest failed! 1>&2
	exit 1
fi

dddctl start -I QWERAFSDFATETWQR -f `pwd`/$i
#delphinusdnsd  -l -f `pwd`/$i -s `pwd`/control.sock

sleep 3

case $1 in

"filter")
	dig -p 9999 @127.0.0.1 checkrefused.tld a | grep REFUSED
	if [ $? -ne 0 ]; then
		RETCODE=1
	else
		RETCODE=0
	fi	
	;;

esac
	
sleep 2

dddctl stop -I QWERAFSDFATETWQR > /dev/null 2>&1
sleep 3

if [ $RETCODE -eq 0 ]; then
	echo OK
else
	#cat output.2
	echo "-->  FAILURE retcode $RETCODE"
	exit $RETCODE
fi

exit 0
