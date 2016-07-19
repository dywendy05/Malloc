/*
 * mm.c
 *
 * 1. This Malloc model uses Segregaed Free lists, and First Fit in search; 
 * 2. An allocated block has a WSIZE header with contains the block size,
      with the last bit indicating its allocate status, and the second 
	  but last bit indicating the allocate status of its previous block;
 * 3. Free blocks are segreated (by size) to lists of 0~16, 17~32, 33~64,...,
      2049~5096, >5096. Each list has a DSIZE root at the start of the heap,
	  containting the address of the first free block in the list;
 * 4. A free block has a similar header as that in an allocated block,
      and it also has a WSIZE footer at the end of the block, containing 
	  only the block size; Following the header is a WSIZE prev_pnt pointing 
	  to the previous free block in free list, and it then follows a WSIZE 
	  next_pnt pointing to the next free block in free list;
 * 5. No consecutive free blocks are allowed;
 * 6. Because a free block is at lest 4*WSIZE(16 bytes), thus the minimal
      block size is set to be 16, and so in malloc, size is rounned up to
	  multiples of 16 bytes after a WSIZE(header) is added;
 * 7. Following the free list roots is a WSIZE PROLOGUE, with value equals 3,
      indicating that the block size is 0, it's allocated and its previous
	  block is also allocated; Following the PROLOUGE is the header
	  of the first block;
 * 8. At the end of the heap is a WSIZE EPILOUGE, containing values of 
      3 or 1, depending on the allocate status of the last block;
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


#define max(a, b) ((a < b) ? b : a)
#define min(a, b) ((a < b) ? a : b)

/* Alignment */
#define ALIGN(sz) ((sz % 8) ? (((sz / 8) + 1) * 8) : sz)

#define MAX_HEAPSIZE (100*(1<<20))   
#define RM_HEAPSIZE ((size_t)(MAX_HEAPSIZE) - mem_heapsize())

/* Define Macros */
#define WSIZE 4   /* Word and header/footer size (bytes) */
#define DSIZE 8   /* Double word size(bytes) */
#define CHUNKSIZE (mem_pagesize())

/* Pack a usize, the allocate bits of the current block and the previous block into a word */
#define PACK(usize, prev_alloc, alloc)  ( (usize) | (prev_alloc<<1) | (alloc))

/* Read and write and a word at address p */
#define GET(p) (*(unsigned int *)(p))
#define PUT(p, val)  (*(unsigned int *)(p)=(val))

/* Given block ptr bp, compute address of its header and footer */
#define HDRP(bp) ((char *)(bp) - WSIZE)
#define GET_SIZE(p) (GET(HDRP(p)) & ~0x7)
#define FTRP(bp) ((char *)(bp) + GET_SIZE(bp) - DSIZE)

/* Given block ptr bp, compute */
#define NEXT_BLK(bp) ((char *)(bp) + GET_SIZE(bp))
#define PREV_BLK(bp) ((char *)(bp) - (GET((char *)bp - DSIZE) & ~0x7))

/* Get the allocate bits of the current block and the adjacent blocks */
#define ALLOC(p) (GET(HDRP(p)) & 0x1)
#define PREV_ALLOC(p) (GET((char *)(p) - DSIZE) & 0x1)
#define NEXT_ALLOC(p) (GET(HDRP(NEXT_BLK(p))) & 0x1)

/* Macros for Prologue, Epilogue and start pointers of each free_list  */
#define SEG_NUM 8
#define PAD_SIZE ((SEG_NUM + 1) * DSIZE)
#define LAUNCH_SIZE (PAD_SIZE * 2)
#define PROLOGUE ((void *)((char *)mem_heap_lo() + SEG_NUM * DSIZE))
#define EPILOGUE ((void *)((char *)mem_heap_hi() - WSIZE + 1))
/* i is index of the free lists*/
#define GET_PTR(p) (((*(unsigned int *)(p)) == 0) ? ((void *)NULL) : \
                    ((void *)((*(unsigned int *)(p)) | 0x800000000)))
#define PUT_PTR(p, ptr) ((*(unsigned int *)(p)) = (unsigned int)((size_t)(ptr)))
#define LIST_HEAD(i) ((void *)((char *)mem_heap_lo() + (DSIZE * i))) 
#define GET_HEAD(i) ((void *)(*(size_t *)(LIST_HEAD(i))))
#define PUT_HEAD(i, ptr) ((*(size_t *)(LIST_HEAD(i))) = (size_t)(ptr))

/* Free list pointer arithmetic */
#define PREV_PTR(p) (GET_PTR(p))
#define NEXT_PTR(p) (GET_PTR((char *)p + WSIZE))
#define PUT_PREV_PTR(p, ptr) (PUT_PTR(p, ptr))
#define PUT_NEXT_PTR(p, ptr) (PUT_PTR(((char *)p + WSIZE), ptr))


/* Static helper functions */

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
    dbg_printf("\n\nmm_init called \n");
	dbg_printf("LAUNCH_SIZE is %d\n", LAUNCH_SIZE);
    if((mem_sbrk(LAUNCH_SIZE)) == (void *)-1)
        return -1;

    unsigned int i = 0;
    for(; i < SEG_NUM; i++) 
        PUT_HEAD(i, NULL);
    
	size_t size = PAD_SIZE;
	void *start_blk = (void *)((char *)PROLOGUE + DSIZE);

	PUT(HDRP(start_blk), size);
	PUT((char *)start_blk + size - DSIZE, size);
	insert(start_blk, size);
	
    PUT(PROLOGUE, 1);
    PUT(EPILOGUE, 1);

    dbg_printf("PROLOGUE is %p (0x%x), Epilogue is %p (0x%x), heap_hi is %p\n", 
	            PROLOGUE, GET(PROLOGUE),  EPILOGUE, GET(EPILOGUE), 
				mem_heap_hi());
  
	dbg_print_free_list(9);
    return 0;
}


/*
 * malloc : Use First Fit 
 */
void *malloc (size_t size) 
{
	dbg_printf("\nMalloc: size is %lx \n", size);

    if(size > MAX_HEAPSIZE - PAD_SIZE)
        return NULL;
    if(size == 0) return NULL ;

    size = ALIGN(size) + DSIZE;

	void *p = search(size);
    /* Available free block NOT found */
    if(p == NULL) {
		if(extend(size) == NULL)
			return NULL;
		p = search(size);	
		if(p == NULL) {
			dbg_printf("\nError: search failed after extension\n");
			return NULL;
		}
	}
    
	delete(p);
	allocate(p, size);
    
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
	dbg_printf("\nRealloc: %p, size is 0x%x", ptr, (unsigned int)size);
/*	if(ptr != NULL)
		dbg_printf("(HD:0x%x), next blk is %p(0x%x)", GET(HDRP(ptr)), 
				   NEXT_BLK(ptr), GET(HDRP(NEXT_BLK(ptr))));
	else dbg_printf("\n");
*/

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
	
	size = ALIGN(size) + DSIZE;
	size_t oldsize = GET_SIZE(ptr);
	if(size <= oldsize) {
		allocate(ptr, size);
		return ptr;
	}

	if(!NEXT_ALLOC(ptr) && (GET_SIZE(NEXT_BLK(ptr)) + oldsize >= size)) {
		void *next = NEXT_BLK(ptr);
		size_t newsize = oldsize + GET_SIZE(next);
		delete(next);
		PUT(HDRP(ptr), newsize);
		allocate(ptr, size);
		return ptr;
	}
	
	void *newptr;
	if((newptr = malloc(size)) == NULL)
			return NULL;
	
	//copy the contents in the old block to the new block;
	for(unsigned int i = 0; i != oldsize - DSIZE; ++i) 
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
static inline unsigned int list(size_t size)
{
	size_t cut = (1 << 5), i = 1;
	while(i < 8 && size > cut) {
		cut <<= 1;
		++i;
	}
	return (8 - i);
}

static inline void * search(size_t size) 
{
	dbg_printf("In search, size is 0x%x \n", (unsigned int)size);
	void *ptr = NULL;
	for(unsigned int i = 0; i != 8; ++i) {
		if(GET_HEAD(i) != NULL) { 	
			ptr = GET_HEAD(i);
			break;
		}
	}
	while(ptr != NULL) {
		dbg_printf("Block %p(HD: 0x%x)\n", ptr, GET(HDRP(ptr)));
		if(GET(HDRP(ptr)) >= size)
			break;
		ptr = NEXT_PTR(ptr);
	}
	dbg_printf("After search, returned ptr is %p\n", ptr);

	return ptr;
}

//extend policy: extend_size = min{max{min_size, mem_heapsize()}, RM_HEAPSIZE}
static inline void *extend(size_t min_size)
{
	dbg_printf("extend called, heapsize is 0x%x, min_size is 0x%x\n",
				(unsigned int)mem_heapsize(),(unsigned int)min_size);
	dbg_print_free_list(20);

	if(RM_HEAPSIZE < min_size)
		return NULL;

	size_t size = min(RM_HEAPSIZE, 
					  max(min_size, min(mem_heapsize(), mem_pagesize())));

	dbg_printf("The size to extend is 0x%x\n", (unsigned int)size);

	void *newptr = (void *)((char *)mem_heap_hi() + 1);
	if(mem_sbrk(size) == (void *)-1)
		return NULL;
	
	PUT(EPILOGUE, 1);
	PUT(HDRP(newptr), size);
	PUT(((char *)EPILOGUE - WSIZE), size);
	coalesce(newptr);

	dbg_printf("After extend, heapsize is 0x%x\n",
				(unsigned int)mem_heapsize());
	dbg_print_free_list(30);
	return newptr; 
}

static inline void delete(void *ptr)
{
	dbg_printf("In delete, ptr is %p(HD: 0x%x)\n", ptr, GET(HDRP(ptr)));
	if(GET_SIZE(ptr) < 16)
		return;

	void *prev = PREV_PTR(ptr);
	void *next = NEXT_PTR(ptr);
	if(prev != NULL) {
		dbg_printf("prev is %p, next is %p", prev, next);
		PUT_NEXT_PTR(prev, next);
		if(next != NULL) 
			PUT_PREV_PTR(next, prev);
	}
	else {
		unsigned int i = list(GET_SIZE(ptr));
		PUT_HEAD(i, next);
		if(next != NULL) 
			PUT_PREV_PTR(next, NULL);
	}
	return;
}

static inline void insert(void *ptr, size_t size)
{
	if(size < 16)
		return;
	unsigned int i = list(size);
	void *next = GET_HEAD(i);
	PUT_HEAD(i, ptr);
	PUT_PREV_PTR(ptr, NULL);
	PUT_NEXT_PTR(ptr, next);
	
	if(next != NULL) 
		PUT_PREV_PTR(next, ptr);
	return;
}

static inline void allocate(void *ptr, size_t size) 
{
	dbg_printf("In allocate: %p(0x%x), size is 0x%x\n", 
				ptr, GET(HDRP(ptr)), (unsigned int)size);
	size_t bsize = GET_SIZE(ptr);
	PUT(HDRP(ptr), size + 1);
	PUT(((char *)ptr + size - DSIZE), size + 1); //put footer;
	if(size < bsize) {
		PUT(HDRP((char *)ptr + size), bsize - size);
		PUT(((char *)ptr + bsize - DSIZE), bsize - size);
		coalesce((void*)((char *)ptr + size));
	}
	return;
}

static void coalesce(void *ptr) 
{
	size_t size = GET_SIZE(ptr);
	unsigned int prev_alloc = PREV_ALLOC(ptr), next_alloc = NEXT_ALLOC(ptr);
	dbg_printf("In coalesce: %p(0x%x),prev is %p(0x%x), next is %p(0x%x)\n",
				ptr, GET(HDRP(ptr)), PREV_BLK(ptr), GET(HDRP(PREV_BLK(ptr))), 
				NEXT_BLK(ptr), GET(HDRP(NEXT_BLK(ptr))));
	
	if(!prev_alloc) {
		void *prev = PREV_BLK(ptr);
		size += GET_SIZE(prev);	
		delete(prev);
		if(!next_alloc) {
			void *next = NEXT_BLK(ptr);
			size += GET_SIZE(next);
			delete(next);
		}
		PUT(HDRP(prev), size);
		PUT(((char *)(prev) + size - DSIZE), size);
		insert(prev, size);

		dbg_printf("After coalesce\n");
		dbg_print_free_list(30);	
		return;
	}
	if(!next_alloc) {
		void *next = NEXT_BLK(ptr);
		size += GET_SIZE(next);
		delete(next);	
	}
	PUT(HDRP(ptr), size);
	PUT(((char *)(ptr) + size - DSIZE), size);
	insert(ptr, size);

	dbg_printf("After coalesce\n");
	dbg_print_free_list(30);	
	return;
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
	if(!in_heap(PROLOGUE)) 
        printf("Error: PROLOGUE %p(0x%x) out of heap\n", 
				PROLOGUE, GET(PROLOGUE));
	if(!in_heap(EPILOGUE))
		printf("Error: EPILOUGE %p(0x%x) out of heap\n", 
				EPILOGUE, GET(EPILOGUE));
	if(GET(PROLOGUE) != 1)
		printf("Error: PROLOGUE %p(0x%x) value not correct\n", 
				PROLOGUE, GET(PROLOGUE));
	if((GET(EPILOGUE) != 1))
		printf("Error: EPILOUGE %p(0x%x) value not corroct\n", 
				EPILOGUE, GET(EPILOGUE));

	//Heap checking;
	int cnt1 = 0;
	void *next;
    void *p = (void *)((char *)PROLOGUE + DSIZE); //Start from the 1st block;
	while(p < EPILOGUE) {
		if(!bounded(p))
			printf("Error: %p(HD: 0x%x) out of bound\n", p, GET(HDRP(p)));
		if(!aligned(p)) 
			printf("Error: %p(HD: 0x%x) not aligend\n", p, GET(HDRP(p)));
		if(GET(HDRP(p)) != GET(FTRP(p))) {
			printf("Error: Header(0x%x) and footer(0x%x) of blcok %p " 
				  "do not match\n", GET(HDRP(p)), GET(FTRP(p)), p);
		}
		next = NEXT_BLK(p);
		if(!ALLOC(p) && !ALLOC(next)) {
			printf("Error: adjacent free blocks: %p(HD: 0x%x), %p(HD: 0x%x)\n", 
					p, GET(HDRP(p)), next, GET(HDRP(next)));
		}
		if(!ALLOC(p)) {
			if(GET_SIZE(p) > 8 )
				++cnt1;
			printf("Free block: Addr. %p, HD: 0x%x, FT: 0x%x\n", 
						p, GET(HDRP(p)), GET(FTRP(p)));
		}
		p = next;		   
	}
 
    //Free list checking;
	int cnt2 = 0;
	unsigned int i = 0;
	void *prev;
	for(; i < SEG_NUM; i++) {
		printf("Free list index: %d\n", i);

	    p = GET_HEAD(i);
		
		while(p != NULL) {
			if(!bounded(p)) {
				printf("Error: %p(HD: 0x%x) is out of bound\n", 
						p, GET(HDRP(p)));
				print_free_list(20);
			}
			if(!aligned(p)) {
				printf("Error: %p(HD: 0x%x) is not aligned\n", 
						p, GET(HDRP(p)));
				print_free_list(20);
			}
			if(ALLOC(p)) {
				printf("Error: allocatd block %p(HD: 0x%x) in a free list\n", 
					   p, GET(HDRP(p)));
				print_free_list(20);
			}
			
			prev = PREV_PTR(p);
			if(prev == NULL) { //p is the first block;
				if(p != GET_HEAD(i)) {
                    printf("Error: address(%p) in the head of %uth list "
							"doee not match its first block %p(HD: 0x%x)\n", 
							GET_HEAD(i), i, p, GET(HDRP(p)));
					print_free_list(20);
				}
			}
			else {
			    if(NEXT_PTR(prev) != p) {
					printf("Error: next ptr for the prev ptr(%p) of %p is %p\n"
							,prev, p, NEXT_PTR(prev));
					print_free_list(20);
				}
			}

			if(list(GET_SIZE(p)) != i) {
				printf("Error: Address %p(HD: 0x%x) does not match its "
					   "free list #%u\n", p, GET(HDRP(p)), i);
				print_free_list(20);
			}

			prev = p;
			p = NEXT_PTR(p);
			++cnt2;
		}
	}  
	
	if(cnt1 != cnt2) {
	    printf("Error: Number of free blocks is %d from heap checking,"
		       " while it's %d from free list checking\n", cnt1, cnt2);
		print_free_list(20);
		exit(0);
	}
    return;
}

static void print_free_list(unsigned int i)
{
	void *p;
	if(i < 8) {
		printf("Root of free list %d is: %p\n", i, GET_HEAD(i));

		p = GET_HEAD(i);
		while(p != NULL) {
		    printf("Address: %p, HD: 0x%x, prev: %p, next %p, FT: 0x%x\n",
				   p, GET(HDRP(p)), PREV_PTR(p), NEXT_PTR(p), GET(FTRP(p)));

			p = NEXT_PTR(p);
		}

		return;
	}
    for(unsigned int j = 0; j < SEG_NUM; j++) {
	    printf("Root of free list %d is: %p\n", j, GET_HEAD(j));

		p = GET_HEAD(j);
		while(p != NULL) {
		    printf("Address: %p, HD: 0x%x, prev: %p, next %p, FT: 0x%x\n",
				   p, GET(HDRP(p)), PREV_PTR(p), NEXT_PTR(p), GET(FTRP(p)));

			p = NEXT_PTR(p);
		}
		printf("\n");
	}
	return;
}
