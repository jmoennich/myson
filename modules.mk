mod_myson.la: mod_myson.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_myson.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_myson.la
