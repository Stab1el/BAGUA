#include <stdint.h>

#define GLIBC_VERSION 231
#define PTR_SIZE 8  // 8 in x64

#if GLIBC_VERSION == 231 // glibc 2.31
#define MAIN_ARENA_BASE 0x7ffff7facb80
#define FASTBIN_OFFSET 2*PTR_SIZE
#define NB_FASTBINS 10
#define BINS_OFFSET (FASTBIN_OFFSET + NB_FASTBINS*PTR_SIZE + 2*PTR_SIZE)
#define NBINS 128
#define HEAP_BASE 0x555555560000
#define HAS_TCACHE 1
#define TCACHE_MAX_BINS 64
#define TCACHE_COUNT_OFFSET 0x00
#define TCACHE_ENTRY_OFFSET 0x90

#elif GLIBC_VERSION == 223 // gilbc 2.23
#define MAIN_ARENA_BASE 0xb7fbc780
#define NB_FASTBINS 10
#define FASTBIN_OFFSET 2*PTR_SIZE
#define BINS_OFFSET (FASTBIN_OFFSET + NB_FASTBINS*PTR_SIZE + 2*PTR_SIZE)
#define NBINS 128
#define HEAP_BASE 0x804b000
#define HAS_TCACHE 0


#endif

// hole type enumation
#define ALLOCATED_CHUNK 1
#define HOLE_TCACHE_BIN 2
#define HOLE_FAST_BIN   3
#define HOLE_NORMAL_BIN 4
#define HOLE_UNSORTED_BIN 5
#define TOP_CHUNK 6
#define HOLE_LAST_REMAINDER 7

struct _hole {
   uint64_t addr;
   uint64_t size;
   uint8_t type;
   uint8_t pnum;
   uint8_t op_index;
   uint64_t alloc_index;
} __attribute__((packed));
typedef struct _hole T_HOLE;
