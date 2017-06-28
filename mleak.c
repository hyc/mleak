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
#include <unistd.h>

#include <signal.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include "mleak.h"

#ifndef ML_STACK
#define ML_STACK	24
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
#if 1
	unw_cursor_t cursor;
	unw_context_t uc;
	int i;

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);
	for (i=0; i<stknum; i++) {
		if (unw_step(&cursor) <= 0)
			break;
		unw_get_reg(&cursor, UNW_REG_IP, (unw_word_t *)&stk[i]);
	}
	return i;
#else
	int i, stop;
	void *ptr;
	for (i=0, stop=0; i<stknum && !stop; i++) {
		switch(i) {
		case 0: if (!(ptr=__builtin_frame_address(0))) {stknum = 0; stop=1;} break;
		case 1: if (!(ptr=__builtin_frame_address(1))) {stknum = 1; stop=1;} break;
		case 2: if (!(ptr=__builtin_frame_address(2))) {stknum = 2; stop=1;} break;
		case 3: if (!(ptr=__builtin_frame_address(3))) {stknum = 3; stop=1;} break;
		case 4: if (!(ptr=__builtin_frame_address(4))) {stknum = 4; stop=1;} break;
		case 5: if (!(ptr=__builtin_frame_address(5))) {stknum = 5; stop=1;} break;
		case 6: if (!(ptr=__builtin_frame_address(6))) {stknum = 6; stop=1;} break;
		case 7: if (!(ptr=__builtin_frame_address(7))) {stknum = 7; stop=1;} break;
		case 8: if (!(ptr=__builtin_frame_address(8))) {stknum = 8; stop=1;} break;
		case 9: if (!(ptr=__builtin_frame_address(9))) {stknum = 9; stop=1;} break;
		case 10: if (!(ptr=__builtin_frame_address(10))) {stknum = 10; stop=1;} break;
		case 11: if (!(ptr=__builtin_frame_address(11))) {stknum = 11; stop=1;} break;
		case 12: if (!(ptr=__builtin_frame_address(12))) {stknum = 12; stop=1;} break;
		}
	}
	for (i=0; i<stknum; i++)
		switch(i) {
		case 0: stk[i] = (size_t)__builtin_return_address(0); break;
		case 1: stk[i] = (size_t)__builtin_return_address(1); break;
		case 2: stk[i] = (size_t)__builtin_return_address(2); break;
		case 3: stk[i] = (size_t)__builtin_return_address(3); break;
		case 4: stk[i] = (size_t)__builtin_return_address(4); break;
		case 5: stk[i] = (size_t)__builtin_return_address(5); break;
		case 6: stk[i] = (size_t)__builtin_return_address(6); break;
		case 7: stk[i] = (size_t)__builtin_return_address(7); break;
		case 8: stk[i] = (size_t)__builtin_return_address(8); break;
		case 9: stk[i] = (size_t)__builtin_return_address(9); break;
		case 10: stk[i] = (size_t)__builtin_return_address(10); break;
		case 11: stk[i] = (size_t)__builtin_return_address(11); break;
		}
#endif
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

/* Generate output */
static void ml_dump()
{
	void *h;
	struct link_map *lm;
	int fd, len;
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
		/* Only private read/write regions are heap candidates
		 * May or may not be executable
		 */
		if (sscanf(ptr, "%p-%p rw%*1[x-]p %x", &lo, &hi, &off) != 3) {
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

static void ml_sigdump(int sig)
{
	ml_dump();
}

static void ml_fini()
{
	ml_dump();
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
	atexit(ml_fini);
	{
		struct sigaction act = {0};
		act.sa_handler = ml_sigdump;
		act.sa_flags = SA_RESTART;
		sigaction(SIGPROF, &act, NULL);
	}
	ml_malloc = mall;
	ml_calloc = call;
	ml_realloc = rall;
	ml_free = ff;
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
	} else {
		/* on failure original should be unchanged */
		p2[ml_stacknum+1] = ml_magic;
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

	if (!ptr)
		return;

	if (ptr < ml_sh.mh_base || ptr >= ml_sh.mh_end) {
		write(2, WRT("ml_ifree - not our memory\n"));
		exit(1);
	} else if ( (char *)ptr + p[-1] == ml_sh.mh_last) {
		p--;
		ml_sh.mh_last = p;
	}
}
