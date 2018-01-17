#!/bin/sh

cat <<-'EOF'
	static inline int
	get_access_time(volatile char *addr)
	{
		unsigned long long time1, time2;
EOF

if grep -q rdtscp /proc/cpuinfo; then
	cat <<-'EOF'
		unsigned junk;
		time1 = __rdtscp(&junk);
		(void)*addr;
		time2 = __rdtscp(&junk);
	EOF
else
	cat <<-'EOF'
		time1 = __rdtsc();
		(void)*addr;
		_mm_mfence();
		time2 = __rdtsc();
	EOF
fi
cat <<-'EOF'
		return time2 - time1;
	}
EOF
