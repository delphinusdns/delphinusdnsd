DELPHINUSDNSDSRC =      ${.CURDIR}/../../../delphinusdnsd

.PATH:  ${DELPHINUSDNSDSRC}

CONFIG= config1 config2 config3 config4

REGRESS_TARGETS=        test-zinclude tmpfiles

CLEANFILES +=           tmpfiles

test-zinclude: depend

.for i in ${CONFIG}
	@echo "--> testing config file $i"
	@./run.sh $i
.endfor	
	
tmpfiles:
	@rm -f output

clean: tmpfiles

.include <bsd.regress.mk>
