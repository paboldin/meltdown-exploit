
CFLAGS += -O2 -msse2

all: meltdown

meltdown.o: rdtscp.h

meltdown: meltdown.o

rdtscp.h: detect_rdtscp.sh
	./detect_rdtscp.sh >$@

clean:
	rm -f meltdown.o meltdown rdtscp.h
