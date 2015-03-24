OPT=-g
CFLAGS:=$(CFLAGS) $(OPT)

mleak.so:	mleak.c mleak.h
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -pthread -ldl -lunwind

mdump:	mdump.o avl.o mdname.o
	$(CC) -o $@ mdump.o avl.o mdname.o -lbfd
