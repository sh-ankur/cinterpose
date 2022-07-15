CC := gcc
CCLIB := gcc -shared -fPIC -lpthread -ldl
CCFLAGS := -DLINUX=1 -ggdb
PRELOAD := LD_PRELOAD
LIBSUFFIX := so

all: directories interpose.$(LIBSUFFIX) testapp

clean:
	@rm -rf bin lib

directories:
	@mkdir -p bin lib

interpose.$(LIBSUFFIX): src/interpose.c
	$(CCLIB) $(CCFLAGS) -o lib/$@ $<

testapp: src/testapp.c
	$(CC) $(CCFLAGS) -o bin/$@ $<

test: lib/interpose.$(LIBSUFFIX) bin/testapp
	$(PRELOAD)="./lib/interpose.$(LIBSUFFIX)" bin/testapp

.PHONEY: directories all clean test
