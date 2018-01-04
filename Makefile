
CFLAGS += -O0

all: meltdown

meltdown: meltdown.o

clean:
	rm -f meltdown.o meltdown
