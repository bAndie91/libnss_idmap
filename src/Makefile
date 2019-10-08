
libnss_idmap.so:
	gcc -shared -fPIC -DPIC libnss_idmap.c -O2 -Wl,-soname -Wl,libnss_idmap.so.2 -Wl,-version-script -Wl,libnss_idmap.ver -o libnss_idmap.so.2
	ln -snf libnss_idmap.so.2 libnss_idmap.so
