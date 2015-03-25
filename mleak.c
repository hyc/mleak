#define _GNU_SOURCE
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

#define ML_STACK	16
int ml_stacknum = ML_STACK;	/* length of stack trace */

/* hooks */
typedef void *(mallfunc)(size_t);
typedef void *(callfunc)(size_t, size_t);
typedef void *(rallfunc)(void *, size_t);
typedef void (freefunc)(void *);

/* temporary allocators for rtld init */
static mallfunc ml_imalloc;
static callfunc ml_icalloc;
static rallfunc ml_irealloc;
static freefunc ml_ifree;

/* Global variables used to hold actual function addresses.	*/
static mallfunc *ml_malloc = ml_imalloc;
static callfunc *ml_calloc = ml_icalloc;
static rallfunc *ml_realloc = ml_irealloc;
static freefunc *ml_free = ml_ifree;

#define WRT(STRCONST)	STRCONST, sizeof(STRCONST)-1

static const size_t ml_magic = 0x600FBA11DEAFB0B3L;

static int ml_backtrace(void **stk, int stknum)
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
			p2 = (char *)(lp - 1);
			if (mr.nstk & 1)
				p2 -= sizeof(void *);
			p2 -= mr.nstk * sizeof(void *);
			write(fd, &mr, sizeof(mr));
			write(fd, p2, mr.nstk * sizeof(void *));
		}
		lp += 2;
	}
}

static char ml_mapbuf[128*1024];

static void ml_fini()
{
	void *h;
	struct link_map *lm;
	int fd, mfd, len;
	char *ptr, *end;

	fd = open("ml.info", O_CREAT|O_WRONLY, 0600);
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
		if (sscanf(ptr, "%p-%p rw-p %x", &lo, &hi, &off) != 3) {
			ptr = strchr(ptr, '\n');
			if (!ptr) break;
			ptr++;
			continue;
		}
		ptr = strchr(ptr, '\n');
		if (!ptr) break;
		ptr++;
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
}

/* my own malloc/realloc/free */
void *malloc(size_t size)
{
	size_t *result, len;
	void *stack[4*ML_STACK];
	int nstk;

	nstk = ml_backtrace(stack, ml_stacknum);
	len = nstk + 1 /* magic */ + 1 /* size + nstk */;
	if (nstk & 1)
		len++;	/* padding */

	result = ml_malloc(size + len * sizeof(void*));
	if (result) {
		memcpy(result, stack, nstk * sizeof(void *));
		result += nstk;
		if (nstk & 1)
			result++;
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
	void *stack[4*ML_STACK];
	int nstk;

	nstk = ml_backtrace(stack, ml_stacknum);
	len = nstk + 1 /* magic */ + 1 /* size + nstk */;
	if (nstk & 1)
		len++;	/* padding */

	size *= nelem;
	result = ml_calloc(1, size + len * sizeof(void*));
	if (result) {
		memcpy(result, stack, nstk * sizeof(void *));
		result += nstk;
		if (nstk & 1)
			result++;
		size |= ((long)nstk << 56);
		*result++ = size;
		*result++ = ml_magic;
	}

	/* return the pointer */
	return(result);
}

void *realloc(void *ptr, size_t size)
{
	size_t *result, *p2, len;
	void *stack[4*ML_STACK];
	size_t osize, tsize;
	int nstk, ostk;
	void *tmp;

	if (!ptr)
		return malloc(size);

	p2 = ptr;
	/* not our pointer? */
	if (p2[-1] != ml_magic)
		return ml_realloc(ptr, size);

	p2 -= 2;
	osize = *p2;
	ostk = osize >> 56;
	osize &= 0xffffffffffffffL;
	tsize = osize;
	if (size < tsize)
		tsize = size;
	tmp = ml_malloc(tsize);
	if (!tmp)
		return NULL;
	memcpy(tmp, ptr, tsize);
	p2[1] = 0;
	if (ostk & 1)
		p2--;
	p2 -= ostk;

	nstk = ml_backtrace(stack, ml_stacknum);
	len = nstk + 1 /* magic */ + 1 /* size + nstk */;
	if (nstk & 1)
		len++;	/* padding */

	result = ml_realloc(p2, size + len * sizeof(void *));
	if (result) {
		memcpy(result, stack, nstk * sizeof(void *));
		result += nstk;
		if (nstk & 1)
			result++;
		size |= ((long)nstk << 56);
		*result++ = size;
		*result++ = ml_magic;
		memcpy(result, tmp, tsize);
	}
	ml_free(tmp);

	/* return the pointer */
	return(result);
}

void free(void *ptr)
{
	size_t *p2;
	size_t osize;
	int ostk;

	if (!ptr) {
		ml_free(ptr);
		return;
	}

	p2 = ptr;
	/* not our pointer? */
	if (p2[-1] != ml_magic) {
		ml_free(ptr);
		return;
	}

	p2 -= 2;
	p2[1] = 0;
	osize = *p2;
	ostk = osize >> 56;
	osize &= 0xffffffffffffffL;
	if (ostk & 1)
		p2--;
	p2 -= ostk;
	ml_free(p2);
}

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

