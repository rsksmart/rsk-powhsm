ifeq ($(COVERAGE),y)
	COVFLAGS = --coverage
else
	COVFLAGS = 
endif
COVFILES = *.gcda *.gcno