# Note that if cross compiling, build with:
#

all: nacl.so

static: libjim-nacl.a

nacl.so: nacl.c tweetnacl.c randombytes.c crypto_hash.c
	$(JIM)/build-jim-ext -I$(JIM) -L$(JIM) $(BUILDOPTS) $^

libjim-nacl.a: nacl.c tweetnacl.c randombytes.c crypto_hash.c
	$(JIM)/build-jim-ext -I$(JIM) -L$(JIM) --static $(BUILDOPTS) $^

test:
	JIMLIB=. $(JIM)/jimsh -e 'package require nacl'
	JIMLIB=. $(JIM)/jimsh test_hash.tcl
	JIMLIB=. $(JIM)/jimsh test_box.tcl
	JIMLIB=. $(JIM)/jimsh test_secretbox.tcl
	JIMLIB=. $(JIM)/jimsh test_sign.tcl
	JIMLIB=. $(JIM)/jimsh test_auth.tcl

clean:
	rm -f *.o *.so *.a
