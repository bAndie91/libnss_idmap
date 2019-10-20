#!/bin/bash

set -e
set -o pipefail
set -u

echo "copy libc.so" >&2
libc_file=`ldd $(which getent) | awk '$1=="libc.so.6"{print $3}'`
cp "$libc_file" .

echo "binary patch libc (overwrite nsswitch.conf location)" >&2
sed -e 's@/etc/nsswitch.conf@..///nsswitch.conf@' -i `basename "$libc_file"`

echo "prepend \"idmap\" to nsswitch.conf" >&2
cat /etc/nsswitch.conf | awk '{if($1=="passwd:" || $1=="group:")
	{$2="idmap [NOTFOUND=return] "$2}; print}' > nsswitch.conf

echo "copy libnss_idmap.so" >&2
cp ../src/libnss_idmap.so ../src/libnss_idmap.so.2 .

echo "binary pacth libnss_idmap (overwrite idmap config file location)" >&2
sed -e 's@/etc/nss.d/idmap@.//////////idmap@' -i libnss_idmap.so.2


for dir in test-*/
do
	echo "test case: $dir ..." >&2
	
	set +e
	set +o pipefail
	(
		cd "$dir"
		LD_LIBRARY_PATH=.. ./run
	)
	test_err=$?
	set -e
	set -o pipefail
	
	echo -n "test case: $dir => " >&2
	
	if [ $test_err = 0 ]
	then
		echo "PASS" >&2
	else
		echo "FAIL ($test_err)" >&2
	fi
done
