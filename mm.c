/*
 * mm.c
 *
 Segregated(16 segs in total), best fit, double linked, FIFO;
    Each list has a root and a tail which points to the last free block;
 Seg cuts: 2^4 - 2^5, 2^5 - 2^6, 2^6 - 2^7, 2^7 - 2^8, 2^8 - 2^9, 2^9 - 2^10,
           2^10 - 2^11, 2^11 - 2^12, 2^12 - 2^13, 2^13 - 2^14, 2^14 - 2^15, 
           2^15 - 2^16, 2^16 - 2^17, 2^17 - 2^18, 2^18 - 2^19, 2^19-;
 Free blocks: header, next_ptr, prev_next, footer; 
    headers and footers contain sizes only.
 Alloctedd blocks: header + effcient data; 
    headers: size + alloc. bit of the prev. blk + alloc bit of this block;
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
#define SEG_NUM 16
#define SEG_SIZE WSIZE
#define LAUNCH_SIZE ((SEG_NUM) * SEG_SIZE + 2 * WSIZE )
#define PROLOGUE (mem_heap_lo())
#define FIRST_BLK ((void *)(char *)(PROLOGUE) + (SEG_NUM) * SEG_SIZE + 2 * WSIZE)
#define EPILOGUE ((void *)((char *)(mem_heap_hi()) + 1 - WSIZE))
/* i is index of the free lists: 0, 1, 2 ...*/
#define GET_PTR(p) (((*(unsigned int *)(p)) == 0) ? ((void *)NULL) : \
                    ((void *)((*(unsigned int *)(p)) | 0x800000000)))
#define PUT_PTR(p, ptr) ((*(unsigned int *)(p)) = (unsigned int)((size_t)(ptr)))
#define LIST_HEAD(i) ((void *)((char *)(PROLOGUE) + WSIZE + (i) * SEG_SIZE)) 
//#define LIST_TAIL(i) ((void *)((char *)(PROLOGUE) + DSIZE + (i) * SEG_SIZE)) 
#define GET_HEAD(i) GET_PTR(LIST_HEAD(i))
//#define GET_TAIL(i) GET_PTR(LIST_TAIL(i))
#define PUT_HEAD(i, ptr) (PUT_PTR(LIST_HEAD(i), (ptr)))
//#define PUT_TAIL(i, ptr) (PUT_PTR(LIST_TAIL(i), (ptr)))

/* Free list pointer arithmetic */
#define NEXT_PTR(p) (GET_PTR(p))
#define PREV_PTR(p) (GET_PTR((char *)(p) + WSIZE))
#define PUT_NEXT_PTR(p, ptr) (PUT_PTR((p), (ptr)))
#define PUT_PREV_PTR(p, ptr) (PUT_PTR(((char *)(p) + WSIZE), (ptr)))

/* Static helper functions */

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
    dbg_printf("\n\nmm_init called \n");
    if((mem_sbrk(mem_pagesize())) == (void *)-1)
        return -1;

    void *root = (void *)((char *)PROLOGUE + WSIZE);
    for(int i = 0; i < SEG_NUM; ++i) {
        PUT_PTR(root,  NULL);
        root = (void *)((char *)root + SEG_SIZE);
    }
    
    dbg_print_free_list();
	size_t size = mem_pagesize() - LAUNCH_SIZE;
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
	dbg_printf("size is now 0x%lx, list index is %d \n", size, list(size));

	void *p = NULL;
	for(int i = list(size); i < SEG_NUM; ++i) {
        p = GET_HEAD(i);
        dbg_printf("i is %d, root is %p( %p)\n", i,LIST_HEAD(i), GET_HEAD(i)); 
        while(p != NULL) {
	        if(GET_SIZE(p) >= size)
                break;
            p = NEXT_PTR(p);
		}
        if(p != NULL)
            break;
	}
    dbg_printf("Searched p is %p\n", p);
    /* If available free block NOT found, ask for extra heap */
    if(p == NULL) {
		if((p = extend(size)) == NULL)
			return NULL;
//        dbg_print_free_list();
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
    size = ALIGN(size, mem_pagesize());

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
	unsigned int i = list(size);
	void *prev = LIST_HEAD(i);
    void *p = GET_HEAD(i);

    while(p != NULL) {
        if(GET_SIZE(p) >=  size)
            break;
        prev = p;
        p = NEXT_PTR(p);
    }
    dbg_printf("brk3\n");

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

static inline int list(size_t size) 
{
    int b = 0, e = SEG_NUM - 1,  mid = (b + e)/2;
    while(e > b ) {
        if(size >= (1UL << (mid + 4)) && size < (1UL << (mid + 5)))
            return mid;
        else if(size < (1UL << (mid + 4))) 
            e = mid - 1;
        else 
            b = mid + 1;

        mid = (b + e)/2;
    }
    return b;
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
	void *prev;
	for(; i < SEG_NUM; ++i) {
        prev = LIST_HEAD(i);
	    p = GET_HEAD(i);

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

			if(list(GET_SIZE(p)) != i) {
				printf("Error: Address %p(HD: 0x%x) does not match its "
					   "free list index %d\n", p, GET(HDRP(p)), i);
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
	void *p;
    for(int i = 0; i < SEG_NUM; ++i) {
	    printf("Root of free list %d is: %p ( %p)\n", 
                i, LIST_HEAD(i), GET_HEAD(i));

		p = GET_HEAD(i);
		while(p != NULL) {
		    printf("Address: %p(HD: 0x%x, FT: 0x%x), prev: %p, next %p\n",
				   p, GET(HDRP(p)), GET(FTRP(p)), PREV_PTR(p), NEXT_PTR(p));

			p = NEXT_PTR(p);
		}
		printf("\n");
	}
	return;
}
