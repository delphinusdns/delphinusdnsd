DELPHINUSDNSDSRC =      ${.CURDIR}/../../../delphinusdnsd

.PATH:  ${DELPHINUSDNSDSRC}

ZONES= centroid.eu delphinusdns.org

REGRESS_TARGETS=        test-sign kfiles

CLEANFILES +=           kfiles

named-checkzone:
	@test -f /usr/local/sbin/named-checkzone

ldns-verify-zone:
	@test -f  /usr/local/bin/ldns-verify-zone

jdnssec-verifyzone:
	#@test -f /home/pjp/Delphinusdns/tools/jdnssec-tools-0.13/bin/jdnssec-verifyzone

depend: named-checkzone ldns-verify-zone jdnssec-verifyzone 

test-sign: depend

.for i in ${ZONES}
	@echo "--> signing $i zone"
	@dddctl sign -a 8 -K -Z -n $i -i $i -o ${i}.signed	
	@echo "--> runnning dddctl configtest"
	dddctl configtest ${i}.signed
	@echo "--> converting to bind format"
	dddctl bindfile $i ${i}.signed > ${i}.bind
	@echo "--> checking against named-checkzone"
	/usr/local/sbin/named-checkzone ${i} ${i}.bind
	@echo "--> checking against ldns-verify-zone"
	/usr/local/bin/ldns-verify-zone ${i}.bind
	@echo "--> checking against jdnssec-verifyzone"
	#/home/pjp/Delphinusdns/tools/jdnssec-tools-0.13/bin/jdnssec-verifyzone ${i}.bind
.endfor
	@echo "--> If you reach here everything verified"
	@echo "--> OK."
	
kfiles:

.for i in ${ZONES}
	@rm K${i}*key K${i}*private
	@rm ${i}.bind ${i}.signed dsset-${i}.
.endfor

clean: kfiles

.include <bsd.regress.mk>
