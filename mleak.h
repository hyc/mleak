/* malloc tracer for memory leak tracking
 * -- Howard Chu, hyc@symas.com 2015-03-24
 */
typedef enum codes {
	ALLOC = 1, FREE, REALLOC } codes;

typedef struct ml_rec {
	codes code;
	int nstk;
	void *addr;	/* the sole address in an alloc or free */
	/* for an alloc, size_t size comes next */
	/* for a realloc, the old address will be recorded here */
	/* actual stack follows */
} ml_rec;

typedef struct ml_rec2 {	/* used for allocs */
	codes code;
	int nstk;
	void *addr;
	size_t size;
} ml_rec2;

typedef struct ml_rec3 {	/* used for realloc */
	codes code;
	int nstk;
	void *addr;
	size_t size;
	void *orig;
} ml_rec3;

typedef struct ml_info {	/* no longer used */
	void **mi_end;
	void *mi_tail;
	int mi_live;
	void *mi_data[0];
} ml_info;
