/*
 * mm.c
 *
 1. Best fit, double linked, only one free list, which has a root(one word size)
        that points to the first block, and the prev_ptr of the first block
        points to its root;
 2. Free blocks: header, next_ptr, prev_next, footer (each takes a word size); 
        headers and footers contain block sizes only.
 3. Alloctedd blocks: header + allocted data; 
        headers: blk size + alloc. bit of the prev. blk + alloc bit of this blk;
 4. Extend policy: extend multiples of 1/4 of a page size on heap requests;
 5. Graph of heap structure (Prologue and Epilogue both take one word size):
        PROLOGUE, root, a word size pad, 1st block, ..., last block, EPILOGUE;
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
//#define DEBUG
#ifdef DEBUG
# define dbg_printf(...) printf(__VA_ARGS__)
#else
# define dbg_printf(...)
#endif

#ifdef DEBUG
# define dbg_print_free_list(...) print_free_list(__VA_ARGS__)
#else 
#define dbg_print_free_list(...)
#endif

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */


#define max(a, b) (((a) < (b)) ? (b) : (a))
#define min(a, b) (((a) < (b)) ? (a) : (b))


/* Alignment */
#define ALIGN(sz, n) (((sz) % (n)) ? (((size_t)((sz)/(n)) + 1) * (n)) : (sz))

/* Minimal block size and cut-off point to devide*/
#define MIN_BLK 16
#define DEVIDE_CUT 16
/* Define Macros */
#define WSIZE 4   /* Word and header/footer size (bytes) */
#define DSIZE 8   /* Double word size(bytes) */

/* Read and write and a word at address p */
#define GET(p) (*(unsigned int *)(p))
#define PUT(p, sz) (*(unsigned int *)(p)= (sz))
// Pack of size, allocate bits for the previous block and this block;
#define PUT_ALL(p, sz, prev, alloc) (PUT((p), ((sz) + 2 * (prev) + (alloc))))

/* Given block ptr bp, compute address of its hd, ft and adjacent blocks */
#define HDRP(bp) ((char *)(bp) - WSIZE)
#define GET_SIZE(p) (GET(HDRP(p)) & ~7)
/* For free blocks only */
#define FTRP(bp) ((char *)(bp) + GET_SIZE(bp) - DSIZE)

#define NEXT_BLK(bp) ((char *)(bp) + GET_SIZE(bp))
/* CAUTION! Only works when the previous block is free! */
#define PREV_BLK(bp) ((char *)(bp) - (GET((char *)(bp) - DSIZE) & ~7))

/* Get the allocate bits of the current block and the adjacent blocks */
#define ALLOC(p) (GET(HDRP(p)) & 1)
#define PREV_ALLOC(p) ((GET(HDRP(p)) >> 1)  & 1)
#define NEXT_ALLOC(p)(GET(HDRP((char *)(p) + GET_SIZE(p))) & 1)
#define PUT_ALLOC(p, alloc) ((alloc) ? PUT(HDRP(p), GET(HDPR(p)) | 1) :  \
                             PUT(HDRP(p), GET(HDRP(p)) & ~1)) 
//Only for allocated blocks; 
#define PUT_PREV_ALLOC(p, prev) ((prev) ? PUT(HDRP(p), GET(HDRP(p)) | 2) : \
                                 PUT(HDRP(p), GET(HDRP(p)) & ~2))

/* Macros for Prologue, Epilogue and start pointers of each free_list  */
#define LAUNCH_SIZE (2 * DSIZE)
#define PROLOGUE (mem_heap_lo())
#define FIRST_BLK ((void *)(char *)(mem_heap_lo() + 2 * DSIZE))
#define EPILOGUE ((void *)((char *)(mem_heap_hi()) + 1 - WSIZE))
/* i is index of the free lists: 0, 1, 2 ...*/
#define GET_PTR(p) (((*(unsigned int *)(p)) == 0) ? ((void *)NULL) : \
                    ((void *)((*(unsigned int *)(p)) | 0x800000000)))
#define PUT_PTR(p, ptr) ((*(unsigned int *)(p)) = (unsigned int)((size_t)(ptr)))
#define LIST_HEAD ((void *)((char *)(mem_heap_lo()) + WSIZE))
#define FIRST_FREE_BLK GET_PTR(LIST_HEAD)
#define PUT_HEAD(ptr) (PUT_PTR(LIST_HEAD, ptr))

/* Free list pointer arithmetic */
#define NEXT_PTR(p) (GET_PTR(p))
#define PREV_PTR(p) (GET_PTR((char *)(p) + WSIZE))
#define PUT_NEXT_PTR(p, ptr) (PUT_PTR((p), (ptr)))
#define PUT_PREV_PTR(p, ptr) (PUT_PTR(((char *)(p) + WSIZE), (ptr)))

/* Extend multiples of EXTEND_SIZE on heap requests*/
#define EXTEND_SIZE (mem_pagesize() / 4)

/* Static helper functions */

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
    dbg_printf("\n\nmm_init called \n");
    if((mem_sbrk(EXTEND_SIZE)) == (void *)-1)
        return -1;

    PUT_HEAD(NULL);

    dbg_print_free_list();
	size_t size = EXTEND_SIZE - LAUNCH_SIZE;
    void *start_ptr = FIRST_BLK;

	PUT(HDRP(start_ptr), size);
    PUT(FTRP(start_ptr), size);

	insert(start_ptr, size);
	
    PUT(PROLOGUE, 1);
    PUT(EPILOGUE, 1);

    dbg_printf("PROLOGUE is %p (0x%x), Epilogue is %p (0x%x), heap_hi is %p\n", 
	            PROLOGUE, GET(PROLOGUE),  EPILOGUE, GET(EPILOGUE), 
				mem_heap_hi());
    return 0;
}


/*
 * malloc : Use First Fit 
 */
void *malloc (size_t size) 
{
	dbg_printf("\nMalloc: size is 0x%lx \n", size);
    dbg_printf("PROLOGUE is %p (0x%x), Epilogue is %p (0x%x), heap_hi is %p\n" 
	           , PROLOGUE, GET(PROLOGUE),  EPILOGUE, GET(EPILOGUE), 
				mem_heap_hi());
    if(size > ((1UL << 32) - LAUNCH_SIZE - WSIZE))
        return NULL;
    if(size == 0) return NULL ;

    size = max(ALIGN(size + WSIZE, 8), MIN_BLK); //Header takse a word size;

    /* Search Policy: first fit from the right list*/

	void *p = FIRST_FREE_BLK;

    while(p != NULL) {
        if(GET_SIZE(p) >= size)
            break;
        p = NEXT_PTR(p);
    }

    dbg_printf("Searched p is %p\n", p);
    /* If available free block NOT found, ask for extra heap */
    if(p == NULL) {
		if((p = extend(size)) == NULL)
			return NULL;
	}
    
	delete_free_blk(p);

    /* Allocate the found free block */	
    size_t bsize = GET_SIZE(p), rmsize = bsize - size;

    void *next;
    if(rmsize > DEVIDE_CUT) {
        PUT_ALL(HDRP(p), size, 1, 1);
        next = (void *)((char *)p + size);
        PUT(HDRP(next), rmsize);
        PUT(FTRP(next), rmsize);
        insert(next, rmsize);
    }
    else {
        PUT_ALL(HDRP(p), bsize, 1, 1);
        next = (void *)((char *)p + bsize);
        PUT_PREV_ALLOC(next, 1);
    }

	return p;
}

/*
 * free
 */
void free(void *ptr) 
{   
    if((ptr == NULL) || !ALLOC(ptr))
        return;

	dbg_printf("\nFree: ptr to be freed is %p (0x%x)\n", ptr, GET(HDRP(ptr)));
	
	coalesce(ptr);
	return;
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *ptr, size_t size) 
{
	dbg_printf("\nRealloc: %p, size is 0x%x\n", ptr, (unsigned int)size);

	if(ptr == NULL)
		return malloc(size);
	if(!size) { //size == 0;
        free(ptr);
		return NULL;
	} 
	if(!ALLOC(ptr)) {
	    printf("Realloc error: block is not alloced!\n");
		return NULL;	
	}
	
   	size = max(ALIGN(size + WSIZE, DSIZE), MIN_BLK);
    dbg_printf("size is 0x%x, ptr is %p(HD 0x%x), next blk is %p(HD 0x%x)\n",
                size, ptr, GET(HDRP(ptr)), NEXT_BLK(ptr),
                GET(HDRP(NEXT_BLK(ptr))));
	size_t oldsize = GET_SIZE(ptr);
    void *next;
	if(size <= oldsize) 
        return ptr;

    next = NEXT_BLK(ptr);
    if(!ALLOC(next) && (oldsize + GET_SIZE(next) >= size)) {
        delete_free_blk(next);

        size_t newsize = oldsize + GET_SIZE(next), rmsize = newsize - size;
        if(rmsize > DEVIDE_CUT) {
            PUT_ALL(HDRP(ptr), size, PREV_ALLOC(ptr), 1);
            next = (void *)((char *)ptr + size);
            PUT(HDRP(next), rmsize);
            PUT(FTRP(next), rmsize);
            insert(next, rmsize);
        }
        else {
            PUT_ALL(HDRP(ptr), newsize, PREV_ALLOC(ptr), 1);
            next = (void *)((char *)ptr + newsize);
            PUT_PREV_ALLOC(next, 1);
        }
        return ptr;
    } 

	void *newptr;
	if((newptr = malloc(size)) == NULL)
			return NULL;
	
	//copy the contents in the old block to the new block;
	for(size_t i = 0; i < oldsize - WSIZE; ++i) 
		*((char *)newptr + i) = *((char *)ptr + i);
		
	free(ptr);

	return newptr;
}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.
 */
void *calloc (size_t nmemb, size_t size) {
    void * ptr;
	size_t bytes = nmemb * size;
    if((ptr = malloc(bytes)) == NULL)
        return NULL;

	memset(ptr, 0, bytes);

    return ptr;
}


/* Static Helper Functions:*/

/* Extend policy: mutilples of page size each time */
static inline void *extend(size_t size)
{
    size = ALIGN(size, EXTEND_SIZE);

	dbg_printf("The size to extend is 0x%x\n", size);

	void *newptr = (void *)((char *)mem_heap_hi() + 1);
	if(mem_sbrk(size) == (void *)-1)
		return NULL;
	
	PUT(EPILOGUE, 1);
	PUT(HDRP(newptr), (GET(HDRP(newptr)) + size));

    dbg_printf("After extend, PROLOGUE is %p (0x%x), Epilogue is %p (0x%x), "
               "heap_hi is %p\n", PROLOGUE, GET(PROLOGUE),  EPILOGUE, 
               GET(EPILOGUE), mem_heap_hi());
	return coalesce(newptr);
}

static inline void delete_free_blk(void *ptr)
{
	dbg_printf("\nIn delete, ptr is %p(HD: 0x%x)\n", ptr, GET(HDRP(ptr)));

	void *prev = PREV_PTR(ptr);
	void *next = NEXT_PTR(ptr);
    
    PUT_NEXT_PTR(prev, next);
	if(next != NULL) 
		PUT_PREV_PTR(next, prev);

    dbg_print_free_list();
	return;
}

/* Insert policy: insert into the place where blocks before it have smaller
                  sizes and blocks after it have equal or greater sizes*/
static inline void insert(void *ptr, size_t size)
{
	dbg_printf("\nIn insert, ptr is %p(HD: 0x%x)\n", ptr, GET(HDRP(ptr)));
	void *prev = LIST_HEAD;
    void *p = FIRST_FREE_BLK;

    while(p != NULL) {
        if(GET_SIZE(p) >=  size)
            break;
        prev = p;
        p = NEXT_PTR(p);
    }

    PUT_NEXT_PTR(prev, ptr);
    PUT_PREV_PTR(ptr, prev);
    PUT_NEXT_PTR(ptr, p);

    if(p != NULL)
        PUT_PREV_PTR(p, ptr);

    dbg_print_free_list();
	return;
}

static void *coalesce(void *ptr) 
{
	size_t size = GET_SIZE(ptr);
	int prev_alloc = PREV_ALLOC(ptr), next_alloc = NEXT_ALLOC(ptr);

	dbg_printf("In coalesce: %p(0x%x),next is %p(0x%x)\n", ptr, 
               GET(HDRP(ptr)), NEXT_BLK(ptr), GET(HDRP(NEXT_BLK(ptr))));
	
    void *next = NEXT_BLK(ptr);
	if(!prev_alloc) {
		void *prev = PREV_BLK(ptr);
		size += GET_SIZE(prev);	
		delete_free_blk(prev);
		
		if(!next_alloc) {
			size += GET_SIZE(next);
			delete_free_blk(next);
            next = NEXT_BLK(next);
		}
		PUT(HDRP(prev), size);
		PUT(FTRP(prev), size);
        PUT_PREV_ALLOC(next, 0);
		insert(prev, size);

		dbg_printf("After coalesce\n");
		return prev;
	}
	if(!next_alloc) {
		size += GET_SIZE(next);
		delete_free_blk(next);
        next = NEXT_BLK(next);    
	}
	PUT(HDRP(ptr), size);
	PUT(FTRP(ptr), size);
    PUT_PREV_ALLOC(next, 0);
	insert(ptr, size);

	dbg_printf("After coalesce\n");
    dbg_print_free_list();
	return ptr;
}


/* Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static inline int in_heap(const void *p) {
    return p <= mem_heap_hi() && p >= mem_heap_lo();
}

static inline int bounded(const void *p) {
	return p < EPILOGUE && p > PROLOGUE;
}
/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static inline int aligned(const void *p) {
    return ((size_t)p / 8) * 8 == (size_t)p;
}

/*
 * mm_checkhexxx */
void mm_checkheap(int lineno) 
{
	printf("mm_checkheap %d\n", lineno);
    //Prologue and Epilouge;
	if(!in_heap(PROLOGUE)) { 
        printf("Error: PROLOGUE %p(0x%x) out of heap\n", 
				PROLOGUE, GET(PROLOGUE));
        exit(1);
    }
	if(!in_heap(EPILOGUE)) {
		printf("Error: EPILOUGE %p(0x%x) out of heap\n", 
				EPILOGUE, GET(EPILOGUE));
        exit(1);
    }
	if(GET(PROLOGUE) != 1) {
		printf("Error: PROLOGUE %p(0x%x) value not correct\n", 
				PROLOGUE, GET(PROLOGUE));
        exit(1);
    }
	if((GET(EPILOGUE) != 1 && GET(EPILOGUE) != 3)) {
		printf("Error: EPILOUGE %p(0x%x) value not corroct\n", 
				EPILOGUE, GET(EPILOGUE));
        exit(1);
    }

	//Heap checking;
	int cnt1 = 0;
	void *next;
    void *p = FIRST_BLK; //Start from the 1st block;
	while(p < EPILOGUE) {
		if(!bounded(p)) {
			printf("Error: %p(HD: 0x%x) out of bound\n", p, GET(HDRP(p)));
            exit(1);
        }
		if(!aligned(p)) {
			printf("Error: %p(HD: 0x%x) not aligend\n", p, GET(HDRP(p)));
            exit(1);
        }

		next = NEXT_BLK(p);
        if(ALLOC(next) && ALLOC(p) != PREV_ALLOC(next)){
            printf("Error: unmatching alloc bit of this block: %p(HD: 0x%x) and"
                   " prev_alloc bit of next block %p(HD:0x%x)\n", 
				   p, GET(HDRP(p)), next, GET(HDRP(next)));
            exit(1);
        }

		if(!ALLOC(p)) {
            if(GET(HDRP(p)) != GET(FTRP(p))) {
                printf("Error: Header(0x%x) and footer(0x%x) of blcok %p " 
                       "do not match\n", GET(HDRP(p)), GET(FTRP(p)), p);
                exit(1);
            }		
            if(!ALLOC(next)) {
                printf("Error: adjacent free blocks: %p(HD: 0x%x) and %p"
                        "(HD: 0x%x)\n", p, GET(HDRP(p)), next, GET(HDRP(next)));
                exit(1);
            }

			++cnt1;
		}
		p = next;		   
	}
 
    //Free list checking;
	int cnt2 = 0, i = 0;
    void *prev = LIST_HEAD;
    p = FIRST_FREE_BLK;

    if(!bounded(prev)) {
        printf("Error: root %p( %p) of list %d is out of bound\n", 
                prev, p, i);
        print_free_list();
        exit(1);
    }		
    while(p != NULL) {
        if(!bounded(p)) {
            printf("Error: %p(HD: 0x%x) of list %d is out of bound\n",
                    p, GET(HDRP(p)), i);
            print_free_list();
            exit(1);
        }
        if(!aligned(p)) {
            printf("Error: %p(HD: 0x%x) of list %d is not aligned\n", 
                    p, GET(HDRP(p)), i);
            print_free_list();
            exit(1);
        }
        if(ALLOC(p)) {
            printf("Error: allocatd block %p(HD: 0x%x) in free list %d\n", 
                   p, GET(HDRP(p)), i);
            print_free_list();
            exit(1);
        }
        
        if(NEXT_PTR(prev) != p) {
            printf("Error: next ptr (list %d) for the prev ptr(%p) of %p "
                    "is %p\n", prev, p, NEXT_PTR(prev));
            print_free_list();
            exit(1);
        }

        prev = p;
        p = NEXT_PTR(p);
        if(p != NULL && GET_SIZE(prev) > GET_SIZE(p)) {
            printf("Error: wrong order of free block %p(HD 0x%x) "
                   "and %p(HD 0x%x)\n", prev, GET(HDRP(prev)),
                   p, GET(HDRP(p)));
            print_free_list();
            exit(1);
        }
        ++cnt2;
    }
	
	if(cnt1 != cnt2) {
	    printf("Error: Number of free blocks is %d from heap checking,"
		       " while it's %d from free list checking\n", cnt1, cnt2);
		print_free_list();
        exit(1);
	}
    return;
}

static void print_free_list()
{
    dbg_printf("PROLOGUE is %p(0x%x), LIST_HEAD is %p(%p), Epilogue is %p(0x%x)"
               "heap_hi is %p\n",  PROLOGUE, GET(PROLOGUE), LIST_HEAD, 
               FIRST_FREE_BLK, EPILOGUE, GET(EPILOGUE), mem_heap_hi());

	void *p = FIRST_FREE_BLK;;
    while(p != NULL) {
        printf("Address: %p(HD: 0x%x, FT: 0x%x), prev: %p, next %p\n",
               p, GET(HDRP(p)), GET(FTRP(p)), PREV_PTR(p), NEXT_PTR(p));

        p = NEXT_PTR(p);
    }
    printf("\n");
	return;
}
