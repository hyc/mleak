/* malloc tracer for memory leak tracking
 * -- Howard Chu, hyc@symas.com 2015-03-24
 */
#define _GNU_SOURCE	/* need this to get RTLD_NEXT defined */
#include <dlfcn.h>

#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include "mleak.h"

#ifndef ML_STACK
#define ML_STACK	12
#endif
int ml_stacknum = ML_STACK;	/* length of stack trace */

static int ml_initing;

/* hooks */
typedef void *(mallfunc)(size_t);
typedef void *(callfunc)(size_t, size_t);
typedef void *(rallfunc)(void *, size_t);
typedef void (freefunc)(void *);

/* temporary allocators for rtld init - dlsym uses malloc */
static mallfunc ml_imalloc;
static callfunc ml_icalloc;
static rallfunc ml_irealloc;
static freefunc ml_ifree;

/* Global variables used to hold actual function addresses.	*/
static mallfunc *ml_malloc = ml_imalloc;
static callfunc *ml_calloc = ml_icalloc;
static rallfunc *ml_realloc = ml_irealloc;
static freefunc *ml_free = ml_ifree;

/* Helper for using string constants with write() */
#define WRT(STRCONST)	STRCONST, sizeof(STRCONST)-1

/* Magic constant identifying our malloc'd blocks */
static const size_t ml_magic = 0x600FBA11DEAFB0B3L;

/* Store a stacktrace into stk with up to stknum levels */
static int ml_backtrace(size_t *stk, int stknum)
{
	unw_cursor_t cursor;
	unw_context_t uc;
	unw_word_t ip;
	int i;

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);
	for (i=0; i<stknum; i++) {
		if (unw_step(&cursor) <= 0)
			break;
		unw_get_reg(&cursor, UNW_REG_IP, (unw_word_t *)&stk[i]);
	}
	return i;
}

/* Scan the memory region from lo to hi looking for
 * malloc'd blocks identified by our magic constant
 */
static void ml_scan(void *lo, void *hi, int fd)
{
	long *lp = lo, *end = hi;

	lp++;
	while (lp < end) {
		if (*lp == ml_magic) {
			char *p2;
			ml_rec2 mr;
			mr.code = ALLOC;
			mr.size = lp[-1];
			mr.nstk = mr.size >> 56;
			mr.size &= 0xffffffffffffffL;
			mr.addr = lp+1;
			p2 = (char *)(lp - 1 - ml_stacknum);
			write(fd, &mr, sizeof(mr));
			write(fd, p2, mr.nstk * sizeof(void *));
		}
		lp += 2;
	}
}

static char ml_mapbuf[128*1024];

/* Generate output at program end */
static void ml_fini()
{
	void *h;
	struct link_map *lm;
	int fd, mfd, len;
	char *ptr, *end;

	/* Output the loader map */
	fd = open("ml.info", O_CREAT|O_WRONLY|O_TRUNC, 0600);
	h = dlopen(NULL, RTLD_LAZY);
	dlinfo(h, RTLD_DI_LINKMAP, &lm);
	for (; lm && lm->l_prev; lm = lm->l_prev);
	for (; lm; lm=lm->l_next)
		if (lm->l_addr) {
			len = strlen(lm->l_name);
			ptr = ml_mapbuf;
			memcpy(ptr, &lm->l_addr, sizeof(lm->l_addr));
			ptr += sizeof(lm->l_addr);
			memcpy(ptr, &len, sizeof(len));
			ptr += sizeof(len);
			memcpy(ptr, lm->l_name, len+1);
			ptr += len+1;
			write(fd, ml_mapbuf, ptr-ml_mapbuf);
		}
	close(fd);

	/* Scan the process maps for heap-like memory regions */
	fd = open("/proc/self/maps", O_RDONLY);
	len = read(fd, ml_mapbuf, sizeof(ml_mapbuf));
	close(fd);
	fd = open("ml.data", O_CREAT|O_WRONLY|O_TRUNC, 0600);
	end = ml_mapbuf + len;
	*end = '\0';
	ptr = ml_mapbuf;
	do {
		void *lo, *hi;
		int off;
		char *name;
		/* Only private read/write regions are heap candidates */
		if (sscanf(ptr, "%p-%p rw-p %x", &lo, &hi, &off) != 3) {
			ptr = strchr(ptr, '\n');
			if (!ptr) break;
			ptr++;
			continue;
		}
		ptr = strchr(ptr, '\n');
		if (!ptr) break;
		ptr++;
		/* anonymous spaces are most likely */
		if (ptr[-2] != ' ') {	/* named space */
			if (ptr[-2] != ']')	/* don't scan file BSS/data */
				continue;
			if (strncmp(ptr-sizeof("[heap]"), "[heap]", sizeof("[heap]")-1))
				continue;		/* don't scan stacks or other stuff */
		}
		ml_scan(lo, hi, fd);
	} while(ptr < end);
	close(fd);
}

/* initialisation of malloc's hooks */
static void ml_init() __attribute__ ((constructor));
static void ml_init()
{
	mallfunc *mall;
	callfunc *call;
	rallfunc *rall;
	freefunc *ff;

	ml_initing = 1;
	mall = dlsym( RTLD_NEXT, "malloc");
	if (!mall) {
		write(2, WRT("ml_init failed to hook malloc!\n"));
		exit(1);
	}
	call = dlsym( RTLD_NEXT, "calloc");
	rall = dlsym( RTLD_NEXT, "realloc");
	ff = dlsym( RTLD_NEXT, "free");
	ml_malloc = mall;
	ml_calloc = call;
	ml_realloc = rall;
	ml_free = ff;
	atexit(ml_fini);
	ml_initing = 0;
}

/* my own malloc/realloc/free */
void *malloc(size_t size)
{
	size_t *result, len;
	int nstk;

	if (ml_initing) return ml_malloc(size);

	len = ml_stacknum + 1 /* magic */ + 1 /* size + nstk */;
	result = ml_malloc(size + len * sizeof(void*));
	if (result) {
		nstk = ml_backtrace(result, ml_stacknum);
		result += ml_stacknum;
		size |= ((long)nstk << 56);
		*result++ = size;
		*result++ = ml_magic;
	}

	/* return the pointer */
	return(result);
}

void *calloc(size_t nelem, size_t size)
{
	size_t *result, len;
	int nstk;

	if (ml_initing) return ml_calloc(nelem, size);

	len = ml_stacknum + 1 /* magic */ + 1 /* size + nstk */;

	size *= nelem;
	result = ml_calloc(1, size + len * sizeof(void*));
	if (result) {
		nstk = ml_backtrace(result, ml_stacknum);
		result += ml_stacknum;
		size |= ((long)nstk << 56);
		*result++ = size;
		*result++ = ml_magic;
	}

	/* return the pointer */
	return(result);
}

/* This is really slow.... */
void *realloc(void *ptr, size_t size)
{
	size_t *result, *p2, len;
	int nstk;

	if (ml_initing) return ml_realloc(ptr, size);

	if (!ptr)
		return malloc(size);

	p2 = ptr;
	/* not our pointer? */
	if (p2[-1] != ml_magic)
		return ml_realloc(ptr, size);

	p2 -= 2;
	p2[1] = 0;
	p2 -= ml_stacknum;

	len = ml_stacknum + 1 /* magic */ + 1 /* size + nstk */;
	result = ml_realloc(p2, size + len * sizeof(void *));
	if (result) {
		nstk = ml_backtrace(result, ml_stacknum);
		result += ml_stacknum;
		size |= ((long)nstk << 56);
		*result++ = size;
		*result++ = ml_magic;
	}

	/* return the pointer */
	return(result);
}

void free(void *ptr)
{
	size_t *p2;

	if (!ptr || ml_initing) {
		ml_free(ptr);
		return;
	}

	p2 = ptr;
	/* not our pointer? */
	if (p2[-1] != ml_magic) {
		ml_free(ptr);
		return;
	}

	p2[-1] = 0;
	p2 -= (2+ml_stacknum);
	ml_free(p2);
}

/* Quick'n'dirty stack-like malloc for use while we try to find
 * the actual malloc functions
 */
#define HEAPSIZE	(1048576*10)
static long ml_hblock[HEAPSIZE];

typedef struct ml_heap {
	void *mh_base;
	void *mh_last;
	void *mh_end;
} ml_heap;

static ml_heap ml_sh = {
	ml_hblock, ml_hblock, (char *)ml_hblock + sizeof(ml_hblock)
};

static void *
ml_imalloc(size_t size)
{
	size_t *new;
	int pad = 2*sizeof(int)-1;

	/* round up to doubleword boundary */
	size += pad + sizeof( size_t);
	size &= ~pad;

	if ((char *) ml_sh.mh_last + size >= (char *) ml_sh.mh_end) {
		write(2, WRT("ml_imalloc exhausted\n"));
		return NULL;
	}
	new = ml_sh.mh_last;
	*new++ = size - sizeof(size_t);
	ml_sh.mh_last = (char *) ml_sh.mh_last + size;
	
	return( (void *)new);
}

static void *
ml_icalloc(size_t n, size_t size)
{
	void *new;

	new = ml_imalloc(n*size);
	if (new)
		memset(new, 0, n*size);
	return new;
}

static void *
ml_irealloc(void *ptr, size_t size)
{
	int pad = 2*sizeof(int)-1;
	size_t *p = (size_t *)ptr;
	size_t *new;

	if ( ptr == NULL) return ml_imalloc(size);

	/* Not our memory? */
	if (ptr < ml_sh.mh_base || ptr >= ml_sh.mh_end) {
		write(2, WRT("ml_irealloc - not our memory\n"));
		return NULL;
	}

	if (!size) {
		ml_ifree(ptr);
		return NULL;
	}

	/* round up to doubleword boundary */
	size += pad + sizeof(size_t);
	size &= ~pad;

	/* Never shrink blocks */
	if (size <= p[-1]) {
		new = p;
	
	/* If reallocing the last block, we can grow it */
	} else if ( (char *)ptr + p[-1] == ml_sh.mh_last) {
		new = p;
		ml_sh.mh_last = (char *) ml_sh.mh_last + size - p[-1];
		p[-1] = size;
	
	/* Nowhere to grow, need to alloc and copy */
	} else {
		new = ml_imalloc(size);
		if (new)
			memcpy(new, ptr, p[-1]);
	}
	return new;
}

static void
ml_ifree(void *ptr)
{
	size_t *p = (size_t *)ptr;

	if (ptr < ml_sh.mh_base || ptr >= ml_sh.mh_end) {
		write(2, WRT("ml_ifree - not our memory\n"));
		exit(1);
	} else if ( (char *)ptr + p[-1] == ml_sh.mh_last) {
		p--;
		ml_sh.mh_last = p;
	}
}
