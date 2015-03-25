OPT=-g
CFLAGS:=$(CFLAGS) $(OPT)

all:	mleak.so	mdump

mleak.so:	mleak.c mleak.h
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl -lunwind

mdump:	mdump.o avl.o mdname.o
	$(CC) -o $@ mdump.o avl.o mdname.o -lbfd
