# Note that if cross compiling, build with:
#

all: nacl.so

static: libjim-nacl.a

nacl.so: nacl.c tweetnacl.c randombytes.c
	$(JIM)/build-jim-ext -I$(JIM) -L$(JIM) $(BUILDOPTS) $^

libjim-nacl.a: nacl.c tweetnacl.c randombytes.c
	$(JIM)/build-jim-ext -I$(JIM) -L$(JIM) --static $(BUILDOPTS) $^

test:
	JIMLIB=. $(JIM)/jimsh -e 'package require nacl'

clean:
	rm -f *.o *.so *.a