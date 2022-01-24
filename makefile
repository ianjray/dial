CC       = clang
SANITIZE = -fsanitize=address -fsanitize=undefined-trap -fsanitize-undefined-trap-on-error
COVERAGE = -fprofile-instr-generate -fcoverage-mapping
OPTS     = $(SANITIZE) $(COVERAGE) -Weverything -Wno-padded -Wno-poison-system-directories

.PHONY : all
all : dial.coverage

%.coverage : %.profdata
	xcrun llvm-cov show $*.unittest -instr-profile=$< $*.c > $@
	! grep " 0|" $@ |grep -ve //UNREACHABLE

%.profdata : %.profraw
	xcrun llvm-profdata merge -sparse $< -o $@

%.profraw : %.unittest
	LLVM_PROFILE_FILE=$@ ./$<

%.unittest : test_dial.c dial.c
	$(CC) $(OPTS) $^ -o $@

.PHONY : clean
clean :
	rm -rf *.coverage *.profdata *.profraw *.unittest*
