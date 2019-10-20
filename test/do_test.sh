#!/bin/bash

set -e
set -o pipefail
set -u

subst_vars()
{
	while read -r expr
	do
		eval "echo \"$expr\""
	done
}

echo "copy libc.so" >&2
libc_file=`ldd $(which getent) | awk '$1=="libc.so.6"{print $3}'`
cp -L "$libc_file" .

echo "binary patch libc (overwrite nsswitch.conf location)" >&2
sed -e 's@/etc/nsswitch.conf@..///nsswitch.conf@' -i `basename "$libc_file"`

echo "prepend \"idmap\" to nsswitch.conf" >&2
cat /etc/nsswitch.conf | awk '{if($1=="passwd:" || $1=="group:")
	{$2="idmap [NOTFOUND=return] "$2}; print}' > nsswitch.conf

echo "copy libnss_idmap.so" >&2
cp -P ../src/libnss_idmap.so ../src/libnss_idmap.so.2 .

echo "binary pacth libnss_idmap (overwrite idmap config file location)" >&2
sed -e 's@/etc/nss.d/idmap@.//////////idmap@' -i libnss_idmap.so.2


for dir in test-*/
do
	echo "" >&2
	echo "test case: $dir ..." >&2
	echo "---------" >&2
	
	getent_args=()
	
	set +e
	set +o pipefail
	(
		cd "$dir"
		. source
		cat idmap.tmpl | subst_vars > idmap
		cat expect.tmpl | subst_vars > expect
		LD_LIBRARY_PATH=.. getent "${getent_args[@]}" | tee output
		
		while read -r expl
		do
			if [ "${expl:0:1}" = '!' ]
			then
				neg='! '
				expl=${expl:1}
			else
				neg=''
			fi
			grep -P "$expl" output
			if [ \( "$neg" = "" -a $? != 0 \) -o \( "$neg" != "" -a $? = 0 \) ]
			then
				echo "Output does not match to expectation: $neg/$expl/" >&2
				exit 1
			fi
		done < expect
		
		exit 0
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
	echo "" >&2
done
