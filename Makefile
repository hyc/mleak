OPT=-g

mleak.so:	mleak.c mleak.h
	$(CC) $(CFLAGS) $(OPT) -shared -fPIC -o $@ $< -pthread -ldl
