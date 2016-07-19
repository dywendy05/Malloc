#ifndef MALLOC_DY
#define MALLOC_DY

#include <stdio.h>

#ifdef DRIVER

/* declare functions for driver tests */
extern void *mm_malloc (size_t size);
extern void mm_free (void *ptr);
extern void *mm_realloc(void *ptr, size_t size);
extern void *mm_calloc (size_t nmemb, size_t size);

#else

/* declare functions for interpositioning */
extern void *malloc (size_t size);
extern void free (void *ptr);
extern void *realloc(void *ptr, size_t size);
extern void *calloc (size_t nmemb, size_t size);

#endif

extern int mm_init(void);

/* This is largely for debugging.  You can do what you want with the
   verbose flag; we don't care. */
extern void mm_checkheap(int verbose);

/* Static helper functions */
static inline unsigned int list(size_t size);
static inline void * search(size_t size);
static inline void *extend(size_t min_size);
static inline void delete(void *ptr);
static inline void insert(void *ptr, size_t size);
static inline void allocate(void *ptr, size_t size); 
static void coalesce(void *ptr);
static void print_free_list(unsigned int i);
#endif
