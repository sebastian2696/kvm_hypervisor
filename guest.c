#include <stddef.h>
#include <stdint.h>
#include "cos_types.h"
#include "cos_config.h"
#include "hypercall_table.h"

typedef enum {
	PGTBL_PRESENT  = 1,
	PGTBL_WRITABLE = 1 << 1,
	PGTBL_USER     = 1 << 2,
	PGTBL_WT       = 1 << 3, /* write-through caching */
	PGTBL_NOCACHE  = 1 << 4, /* caching disabled */
	PGTBL_ACCESSED = 1 << 5,
	PGTBL_MODIFIED = 1 << 6,
	PGTBL_SUPER    = 1 << 7, /* super-page (4MB on x86-32) */
	PGTBL_GLOBAL   = 1 << 8,
	/* Composite defined bits next*/
	PGTBL_COSFRAME   = 1 << 9,
	PGTBL_COSKMEM    = 1 << 10, /* page activated as kernel object */
	PGTBL_QUIESCENCE = 1 << 11,
	/* Flag bits done. */

	PGTBL_USER_DEF   = PGTBL_PRESENT | PGTBL_USER | PGTBL_ACCESSED | PGTBL_MODIFIED | PGTBL_WRITABLE,
	PGTBL_INTERN_DEF = PGTBL_USER_DEF,
} pgtbl_flags_t;

#define KERN_INIT_PGD_IDX (COS_MEM_KERN_START_VA >> PGD_SHIFT)
u32_t boot_comp_pgd[PAGE_SIZE / sizeof(u32_t)] PAGE_ALIGNED = {[0] = 0 | PGTBL_PRESENT | PGTBL_WRITABLE | PGTBL_SUPER,
                                                               [KERN_INIT_PGD_IDX] = 0 | PGTBL_PRESENT | PGTBL_WRITABLE
                                                                                     | PGTBL_SUPER};

static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}


static void out(uint16_t port, uint32_t value) {
	asm("out %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

//int hypercall(uint16_t port, uint32_t data) {
//  int ret = 0;
//  asm(
//    "mov dx, %[port];"
//    "mov eax, %[data];"
//    "out dx, %%eax;"
//    "in %%eax, dx;"
//    "mov %[ret], eax;"
//    : [ret] "=r"(ret)
//    : [port] "r"(port), [data] "r"(data)
//    : "rax", "rdx"
//    );
//  return ret;
//}


void
//kmain(void) {
kmain(int a, int b, int c) {
	const char *p;
//	char *test = "l";
	for (p = "Hello, world!\n"; *p; ++p){
//		hypercall(0xE9, *p);
		out(0xE9, *p);
//        while(1);
//        out(0xE9, *test);
//		while(1);
	}
//	while(1);
//	*(long *) 0x400 = 42;

//	for (;;)
		asm("hlt" : /* empty */ : "a" (42) : "memory");
}
/*
void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	const char *p;
	char *test = "l";
	for (p = "Hello, world!\n"; *p; ++p){
		hypercall(0xE9, *p);
		outb(0xE9, *p);
		out(0xE9, *test);
		while(1);
	}
	while(1);
	*(long *) 0x400 = 42;

	for (;;)
}
*/


//asm("hlt" : /* empty */ : "a" (42) : "memory");
