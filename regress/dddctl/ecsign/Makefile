DELPHINUSDNSDSRC =      ${.CURDIR}/../../../delphinusdnsd

.PATH:  ${DELPHINUSDNSDSRC}

ZONES= centroid.eu delphinusdns.org

REGRESS_TARGETS=        test-sign kfiles
#REGRESS_TARGETS=        test-sign 

CLEANFILES +=           kfiles

ldns-verify-zone:
	@test -f  /usr/local/bin/ldns-verify-zone


depend: ldns-verify-zone

test-sign: depend

.for i in ${ZONES}
	@echo "--> signing $i zone"
	@dddctl sign -a 13 -K -Z -n $i -i $i -o ${i}.signed	
	@echo "--> runnning dddctl configtest"
	dddctl configtest ${i}.signed
	@echo "--> converting to bind format"
	dddctl bindfile $i ${i}.signed > ${i}.bind
	@echo "--> checking against ldns-verify-zone"
	/usr/local/bin/ldns-verify-zone ${i}.bind
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
