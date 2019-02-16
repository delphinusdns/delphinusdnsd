#!/bin/ksh

#set -x

i=$1

dddctl configtest $i > /dev/null
if [ $? -eq 1 ]; then
	echo dddctl configtest failed! 1>&2
	exit 1
fi

(delphinusdnsd  -dvvv -l -f `pwd`/$i -s `pwd`/control.sock > output  2>&1 ) &

sleep 3

case $1 in

"a")
	dddctl query -@127.0.0.1 -P4053 centroid.eu a  > output.2

	grep -q `grep -v '^;' output.2 | grep ,a,` a
	RETCODE=$?
	;;

"aaaa")
	dddctl query -@127.0.0.1 -P4053 centroid.eu aaaa  > output.2

	grep -q `grep -v '^;' output.2 | grep ,aaaa,` aaaa
	RETCODE=$?
	;;

"txt")
	dddctl query -@127.0.0.1 -P4053 centroid.eu txt > output.2

	grep -v '^;' output.2 > tmp
	grep -q -f tmp output.2
	RETCODE=$?
	rm -f tmp
	;;

"nsec3")
	dddctl query -D -@127.0.0.1 -P4053 nsec3 vq9u3o7nealsmj548jergdj0d5oi6d06.centroid.eu. > output.2

	grep -v '^;' output.2 > tmp
	grep -q -f tmp output.2
	RETCODE=$?
	rm -f tmp
	;;

"ns")
	dddctl query -@127.0.0.1 -P4053 centroid.eu ns  > output.2

	grep -q `grep -v '^;' output.2 | grep ,ns,` ns
	RETCODE=$?
	;;


"mx")
	dddctl query -@127.0.0.1 -P4053 centroid.eu mx  > output.2

	grep -q `grep -v '^;' output.2 | grep ,mx,` mx
	RETCODE=$?
	;;

"soa")
	dddctl query -@127.0.0.1 -P4053 centroid.eu soa  > output.2

	grep -q `grep -v '^;' output.2 | grep ,soa,` soa
	RETCODE=$?
	;;

"naptr")
	dddctl query -@127.0.0.1 -P4053 centroid.eu naptr > output.2

	grep -q `grep -v '^;' output.2 | grep ,naptr,` naptr
	RETCODE=$?
	;;

"a-multi")
	dddctl query -@127.0.0.1 -P4053 centroid.eu a  > output.2
	
	RETCODE=0
	for i in `grep -v '^;' output.2 | grep ,a,`; do
		grep -q $i a-multi
		if [ $? -ne 0 ]; then
			RETCODE=$?
		fi
	done
	;;

"aaaa-multi")
	dddctl query -@127.0.0.1 -P4053 centroid.eu aaaa  > output.2
	
	RETCODE=0
	for i in `grep -v '^;' output.2 | grep ,aaaa,`; do
		grep -q $i aaaa-multi
		if [ $? -ne 0 ]; then
			RETCODE=$?
		fi
	done
	;;

"sshfp-multi")
	dddctl query -@127.0.0.1 -P4053 centroid.eu sshfp  > output.2
	
	RETCODE=0
	for i in `grep -v '^;' output.2 | grep ,sshfp,`; do
		grep -q $i sshfp-multi
		if [ $? -ne 0 ]; then
			RETCODE=$?
		fi
	done
	;;

"naptr-multi")
	dddctl query -@127.0.0.1 -P4053 centroid.eu naptr  > output.2
	
	RETCODE=0
	for i in `grep -v '^;' output.2 | grep ,naptr,`; do
		grep -q $i naptr-multi
		if [ $? -ne 0 ]; then
			RETCODE=$?
		fi
	done
	;;

"ns-multi")
	dddctl query -@127.0.0.1 -P4053 centroid.eu ns  > output.2
	
	RETCODE=0
	for i in `grep -v '^;' output.2 | grep ,ns,`; do
		grep -q $i ns-multi
		if [ $? -ne 0 ]; then
			RETCODE=$?
		fi
	done
	;;

"mx-multi")
	dddctl query -@127.0.0.1 -P4053 centroid.eu mx  > output.2
	
	RETCODE=0
	for i in `grep -v '^;' output.2 | grep ,mx,`; do
		grep -q $i mx-multi
		if [ $? -ne 0 ]; then
			RETCODE=$?
		fi
	done
	;;

"rrsig-multi")
	dddctl query -@127.0.0.1 -P4053 -D centroid.eu a  > output.2
	
	RETCODE=0
	for i in `grep -v '^;' output.2 | grep ,rrsig,`; do
		grep -q $i rrsig-multi
		if [ $? -ne 0 ]; then
			RETCODE=$?
		fi
	done
	;;

"rrsig-multi.2")
	dddctl query -@127.0.0.1 -P4053 -D centroid.eu dnskey  > output.2
	
	RETCODE=0
	for i in `grep -v '^;' output.2 | grep ,rrsig,`; do
		grep -q $i rrsig-multi.2
		if [ $? -ne 0 ]; then
			RETCODE=$?
		fi
	done
	;;

"dnskey-multi")
	dddctl query -@127.0.0.1 -P4053 -D centroid.eu dnskey  > output.2
	
	RETCODE=0
	for i in `grep -v '^;' output.2 | grep ,dnskey,`; do
		grep -q $i dnskey-multi
		if [ $? -ne 0 ]; then
			RETCODE=$?
		fi
	done
	;;

esac
	
sleep 2

dddctl stop -s `pwd`/control.sock  > /dev/null 2>&1
sleep 3

if [ $RETCODE -eq 0 ]; then
	echo OK
else
	cat output.2
	echo "-->  FAILURE retcode $RETCODE"
	exit $RETCODE
fi

exit 0
