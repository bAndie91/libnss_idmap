
LIBS = -ldl

ifdef DEBUG
  CCFLAGS = $(CCFLAGS) -g -DDEBUG
endif


libnss_idmap:
	gcc $(CCFLAGS) $(LDFLAGS) $(LIBS) -Wall -D_GNU_SOURCE -shared -fPIC -DPIC -O2 -Wl,-soname -Wl,$@.so.2 -Wl,-version-script -Wl,$@.ver $@.c -o $@.so.2
	ln -snf $@.so.2 $@.so
