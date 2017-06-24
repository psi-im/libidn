AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/lib -I../lib -I$(top_srcdir)/gl -I../gl -DSRCDIR=\"$(abs_srcdir)\" -DTEST_RUN
AM_LDFLAGS = -no-install

LDADD = ../lib/libidn.la

IDN_TESTS = \
 libidn_toascii_fuzzer$(EXEEXT) \
 libidn_tounicode_fuzzer$(EXEEXT)

check_PROGRAMS = $(IDN_TESTS)

libidn_toascii_fuzzer_SOURCES = libidn_toascii_fuzzer.c main.c fuzzer.h
libidn_tounicode_fuzzer_SOURCES = libidn_tounicode_fuzzer.c main.c fuzzer.h

dist-hook:
	find . -name '*.options' -exec cp -v '{}' $(distdir) ';'
	find . -name '*.dict' -exec cp -v '{}' $(distdir) ';'
	find . -name '*.in' -exec cp -vr '{}' $(distdir) ';'
	find . -name '*.repro' -exec cp -vr '{}' $(distdir) ';'

TESTS = $(IDN_TESTS)

clean-local:
	rm -rf *.gc?? *.log lcov coverage.info

oss-fuzz:
	if test "$$OUT" != ""; then \
	for ccfile in *_fuzzer.c; do \
	fuzzer=$$(basename $$ccfile .c); \
	$$CXX $$CXXFLAGS -I$(top_srcdir)/lib -I$(top_srcdir) \
	"$${fuzzer}.c" -o "$${fuzzer}" \
	../lib/.libs/libidn.a $${LIB_FUZZING_ENGINE} -Wl,-Bstatic \
	-lunistring \
	-Wl,-Bdynamic; \
	done; \
	fi

.PHONY: oss-fuzz
