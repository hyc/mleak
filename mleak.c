#define _GNU_SOURCE
#include <pthread.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mleak.h"

static pthread_key_t ml_key;

int ml_stacknum = 16;	/* length of stack trace */
size_t ml_size = 1024*1048576;	/* 1GB */

static int ml_initing;

/* hooks */
typedef void *(mallfunc)(size_t);
typedef void *(callfunc)(size_t, size_t);
typedef void *(rallfunc)(void *, size_t);
typedef void *(mlinfunc)(size_t, size_t);
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
static mlinfunc *ml_memalign;
static mallfunc *ml_valloc;

#define WRT(STRCONST)	STRCONST, sizeof(STRCONST)-1

static void ml_fini()
{
	void *h;
	struct link_map *lm;
	int fd, len;
	char buf[1024], *ptr;

	fd = open("ml.info", O_CREAT|O_WRONLY, 0600);
	h = dlopen(NULL, RTLD_LAZY);
	dlinfo(h, RTLD_DI_LINKMAP, &lm);
	for (; lm && lm->l_prev; lm = lm->l_prev);
	for (; lm; lm=lm->l_next)
		if (lm->l_addr) {
			len = strlen(lm->l_name);
			ptr = buf;
			memcpy(ptr, &lm->l_addr, sizeof(lm->l_addr));
			ptr += sizeof(lm->l_addr);
			memcpy(ptr, &len, sizeof(len));
			ptr += sizeof(len);
			memcpy(ptr, lm->l_name, len+1);
			ptr += len+1;
			write(fd, buf, ptr-buf);
		}
	close(fd);
}

/* initialisation of malloc's hooks */
static void ml_init() __attribute__ ((constructor));
static void ml_init()
{
	mallfunc *mall, *vall;
	callfunc *call;
	rallfunc *rall;
	freefunc *ff;
	mlinfunc *mlin;

	ml_initing = 1;
	(void) pthread_key_create(&ml_key, NULL);
	mall = dlsym( RTLD_NEXT, "malloc");
	if (!mall) {
		write(2, WRT("ml_init failed to hook malloc!\n"));
		exit(1);
	}
	call = dlsym( RTLD_NEXT, "calloc");
	vall = dlsym( RTLD_NEXT, "valloc");
	rall = dlsym( RTLD_NEXT, "realloc");
	mlin = dlsym( RTLD_NEXT, "memalign");
	ff = dlsym( RTLD_NEXT, "free");
	ml_malloc = mall;
	ml_calloc = call;
	ml_realloc = rall;
	ml_free = ff;
	ml_valloc = vall;
	ml_memalign = mlin;
	atexit(ml_fini);
	ml_initing = 0;
}

ml_info *ml_ithread()
{
	char buf[64];
	int fd;
	ml_info *mi;

	sprintf(buf, "ml.%p", (void *)pthread_self());
	fd = open(buf, O_CREAT|O_RDWR, 0600);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	ftruncate(fd, ml_size);
	mi = mmap(NULL, ml_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mi == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	close(fd);
	mi->mi_end = (void **)((char *)mi + ml_size);
	mi->mi_tail = mi->mi_data;
	mi->mi_live = 0;
	pthread_setspecific(ml_key, mi);
	return mi;
}

/* my own malloc/realloc/free */
void *malloc(size_t size)
{
	void *result, **stk;
	ml_rec2 *mr;
	ml_info *mi;

	result = ml_malloc(size);
	if (ml_initing) return result;

	mi = pthread_getspecific(ml_key);
	if (!mi)
		mi = ml_ithread();
	if (mi->mi_live) return result;

	mi->mi_live = 1;
	mr = mi->mi_tail;
	mr->code = ALLOC;
	mr->size = size;
	mr->addr = result;
	stk = (void **)(mr+1);
	if (stk + ml_stacknum >= mi->mi_end) {
		write(2, WRT("out of trace room\n"));
		exit(1);
	}
	mr->nstk = backtrace(stk, ml_stacknum);
	mi->mi_tail = stk + mr->nstk;
	mi->mi_live = 0;

	/* return the pointer */
	return(result);
}

void *calloc(size_t nelem, size_t size)
{
	void *result, **stk;
	ml_rec2 *mr;
	ml_info *mi;

	result = ml_calloc(nelem, size);
	if (ml_initing) return result;

	size *= nelem;

	mi = pthread_getspecific(ml_key);
	if (!mi)
		mi = ml_ithread();
	if (mi->mi_live) return result;

	mi->mi_live = 1;
	mr = mi->mi_tail;
	mr->code = ALLOC;
	mr->size = size;
	mr->addr = result;
	stk = (void **)(mr+1);
	if (stk + ml_stacknum >= mi->mi_end) {
		write(2, WRT("out of trace room\n"));
		exit(1);
	}
	mr->nstk = backtrace(stk, ml_stacknum);
	mi->mi_tail = stk + mr->nstk;
	mi->mi_live = 0;

	/* return the pointer */
	return(result);
}

void *valloc(size_t size)
{
	void *result, **stk;
	ml_rec2 *mr;
	ml_info *mi;

	result = ml_valloc(size);
	if (ml_initing) return result;

	mi = pthread_getspecific(ml_key);
	if (!mi)
		mi = ml_ithread();
	if (mi->mi_live) return result;

	mi->mi_live = 1;
	mr = mi->mi_tail;
	mr->code = ALLOC;
	mr->size = size;
	mr->addr = result;
	stk = (void **)(mr+1);
	if (stk + ml_stacknum >= mi->mi_end) {
		write(2, WRT("out of trace room\n"));
		exit(1);
	}
	mr->nstk = backtrace(stk, ml_stacknum);
	mi->mi_tail = stk + mr->nstk;
	mi->mi_live = 0;

	/* return the pointer */
	return(result);
}

void *realloc(void * ptr, size_t size)
{
	void *result, **stk;
	ml_rec3 *mr;
	ml_info *mi;

	result = ml_realloc(ptr, size);
	if (ml_initing) return result;

	mi = pthread_getspecific(ml_key);
	if (!mi)
		mi = ml_ithread();
	if (mi->mi_live) return result;

	mi->mi_live = 1;
	mr = mi->mi_tail;
	mr->code = REALLOC;
	mr->size = size;
	mr->addr = result;
	mr->orig = ptr;
	stk = (void **)(mr+1);
	if (stk + ml_stacknum >= mi->mi_end) {
		write(2, WRT("out of trace room\n"));
		exit(1);
	}
	mr->nstk = backtrace(stk, ml_stacknum);
	mi->mi_tail = stk + mr->nstk;
	mi->mi_live = 0;

	/* return the pointer */
	return(result);
}

void *memalign(size_t align, size_t size)
{
	void *result, **stk;
	ml_rec2 *mr;
	ml_info *mi;

	result = ml_memalign(align, size);
	if (ml_initing) return result;

	mi = pthread_getspecific(ml_key);
	if (!mi)
		mi = ml_ithread();
	if (mi->mi_live) return result;

	mi->mi_live = 1;
	mr = mi->mi_tail;
	mr->code = ALLOC;
	mr->size = size;
	mr->addr = result;
	stk = (void **)(mr+1);
	if (stk + ml_stacknum >= mi->mi_end) {
		write(2, WRT("out of trace room\n"));
		exit(1);
	}
	mr->nstk = backtrace(stk, ml_stacknum);
	mi->mi_tail = stk + mr->nstk;
	mi->mi_live = 0;

	/* return the pointer */
	return(result);
}

void free(void * ptr)
{
	void **stk;
	ml_rec *mr;
	ml_info *mi;

	ml_free(ptr);
	if (ml_initing) return;

	mi = pthread_getspecific(ml_key);
	if (!mi)
		mi = ml_ithread();
	if (mi->mi_live) return;

	mi->mi_live = 1;
	mr = mi->mi_tail;
	mr->code = FREE;
	mr->addr = ptr;
	stk = (void **)(mr+1);
	if (stk + ml_stacknum >= mi->mi_end) {
		write(2, WRT("out of trace room\n"));
		exit(1);
	}
	mr->nstk = backtrace(stk, ml_stacknum);
	mi->mi_tail = stk + mr->nstk;
	mi->mi_live = 0;
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

