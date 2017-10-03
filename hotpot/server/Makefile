.PHONY: clean

CFLAGS  := -Wall -g
LD      := gcc
LDLIBS  := ${LDLIBS} -lrdmacm -libverbs -lpthread -ldl
DEPS	= client.h fifo.h dsnvm-server.h thpool.h

APPS    := hotpot-server

all: ${APPS}

hotpot-server: init.o network_handler.o dsnvm-us-netcore.o dsnvm-us-netbase.o create_file.o open_file.o fifo.o dsnvm-server.o thpool.o
	${LD} -o $@ $^ ${LDLIBS} $(DEPS)

clean:
	rm -f *.o ${APPS}
