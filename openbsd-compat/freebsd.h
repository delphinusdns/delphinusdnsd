#ifdef __FreeBSD__

#define freezero(a,x)	free(a)
#define recallocarray(a,b,c,d)	reallocarray(a,b,c)

#endif
