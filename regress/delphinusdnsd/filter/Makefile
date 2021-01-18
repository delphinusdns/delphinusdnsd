DELPHINUSDNSDSRC =      ${.CURDIR}/../../../delphinusdnsd

.PATH:  ${DELPHINUSDNSDSRC}

CONFIG= filter

REGRESS_TARGETS=        tmpfiles

CLEANFILES +=           tmpfiles

regress: depend

.for i in ${CONFIG}
	@echo "--> testing config file $i"
	@./run.sh $i
.endfor	
	
tmpfiles:
	@echo rm -f output output.2

clean: tmpfiles

.include <bsd.regress.mk>
