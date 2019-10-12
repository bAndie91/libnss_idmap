
LIBS = -ldl

ifdef DEBUG
  CCFLAGS += -g -DDEBUG
else
  CCFLAGS += -O2
endif


libnss_idmap:
	gcc $(CCFLAGS) $(LDFLAGS) $(LIBS) -Wall -D_GNU_SOURCE -shared -fPIC -DPIC -Wl,-soname -Wl,$@.so.2 -Wl,-version-script -Wl,$@.ver $@.c -o $@.so.2
	ln -snf $@.so.2 $@.so
