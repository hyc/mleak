#include <sys/types.h>
#include <sys/cdefs.h>
#include <new>
extern "C" {
	void *malloc(size_t s);
	void free(void *p);
}

void * operator new(size_t size) throw (std::bad_alloc) {
	void *ret = malloc(size);
	if (!ret) throw std::bad_alloc();
	return ret;
}
void   operator delete(void *p) __THROW { free(p); }
void * operator new[](size_t size) throw (std::bad_alloc)  {
	void *ret = malloc(size);
	if (!ret) throw std::bad_alloc();
	return ret;
}
void   operator delete[](void *p) __THROW { free(p); }
void* operator new(size_t size, const std::nothrow_t& nt) __THROW {return malloc(size); }
void* operator new[](size_t size, const std::nothrow_t& nt) __THROW {return malloc(size);}
void operator delete(void *ptr, const std::nothrow_t& nt) __THROW {free(ptr);}
void operator delete[](void *ptr, const std::nothrow_t& nt) __THROW {free(ptr);}

