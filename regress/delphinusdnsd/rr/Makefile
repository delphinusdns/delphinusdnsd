DELPHINUSDNSDSRC =      ${.CURDIR}/../../../delphinusdnsd

.PATH:  ${DELPHINUSDNSDSRC}

CONFIG= a a-multi soa naptr naptr-multi mx mx-multi ns ns-multi txt aaaa aaaa-multi sshfp-multi rrsig-multi dnskey-multi rrsig-multi.2 nsec3

REGRESS_TARGETS=        test-a tmpfiles

CLEANFILES +=           tmpfiles

test-a: depend

.for i in ${CONFIG}
	@echo "--> testing config file $i"
	@./run.sh $i
.endfor	
	
tmpfiles:
	@rm -f output output.2

clean: tmpfiles

.include <bsd.regress.mk>
