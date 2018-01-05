
CFLAGS += -O2 -msse2

all: meltdown

meltdown: meltdown.o

clean:
	rm -f meltdown.o meltdown
