CFLAGS := -std=gnu11 -Wall -Wmissing-prototypes -Wstrict-prototypes\
	  -fomit-frame-pointer -freg-struct-return -O2

CFLAGS := -fomit-frame-pointer -freg-struct-return

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

all: $(OBJS)

clean:
	rm -f *.o

%.o: %.c
	gcc -lm -lpthread -o $@ $(CFLAGS) $<
