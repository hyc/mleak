OPT=-g
INC=-I/usr/include/libiberty
CFLAGS:=$(CFLAGS) $(OPT) $(INC)

LIBS=mleak.so mleak++.so
PRGS=mdump
OBJS=mleak.o mnew.o mdump.o mdname.o avl.o

all:	$(LIBS) $(PRGS)

clean:
	rm -f $(LIBS) $(PRGS) $(OBJS)

mleak.o:	mleak.c mleak.h
	$(CC) $(CFLAGS) -fPIC -c $<

mnew.o:		mnew.cc
	$(CXX) $(CFLAGS) -fPIC -c $<

mleak.so:	mleak.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -ldl -lunwind

mleak++.so:	mleak.o mnew.o
	$(CXX) $(CFLAGS) -shared -o $@ $^ -ldl -lunwind

mdump:	mdump.o avl.o mdname.o
	$(CC) -o $@ mdump.o avl.o mdname.o -lbfd
