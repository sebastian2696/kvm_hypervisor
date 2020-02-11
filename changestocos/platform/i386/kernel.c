#include "assert.h"
#include "kernel.h"
#include "multiboot.h"
#include "string.h"
#include "boot_comp.h"
#include "mem_layout.h"
#include "chal_cpu.h"

#include <captbl.h>
#include <retype_tbl.h>
#include <component.h>
#include <thd.h>

#define ADDR_STR_LEN 8

struct mem_layout glb_memlayout;
volatile int cores_ready[NUM_CPU];

extern u8_t end; /* from the linker script */

#define MEM_KB_ONLY(x) (((x) & ((1 << 20) - 1)) >> 10)
#define MEM_MB_ONLY(x) ((x) >> 20)

void
kern_memory_setup(struct multiboot *mb, u32_t mboot_magic)
{
	struct multiboot_mod_list *mods;
	struct multiboot_mem_list *mems;
	unsigned int               i, wastage = 0;

	glb_memlayout.allocs_avail = 1;

	if (mboot_magic != MULTIBOOT_EAX_MAGIC) {
		die("Not started from a multiboot loader!\n");
	}
	if ((mb->flags & MULTIBOOT_FLAGS_REQUIRED) != MULTIBOOT_FLAGS_REQUIRED) {
		die("Multiboot flags include %x but are missing one of %x\n", mb->flags, MULTIBOOT_FLAGS_REQUIRED);
	}

	mods = (struct multiboot_mod_list *)mb->mods_addr;
	mems = (struct multiboot_mem_list *)mb->mmap_addr;
	if (mb->mods_count != 1) {
		die("Boot failure: expecting a single module to load, received %d instead.\n", mb->mods_count);
	}

	glb_memlayout.kern_end = &end + PAGE_SIZE;
	assert((unsigned int)&end % RETYPE_MEM_NPAGES * PAGE_SIZE == 0);

	printk("System memory info from multiboot (end 0x%x):\n", &end);
	printk("\tModules:\n");
	for (i = 0; i < mb->mods_count; i++) {
		struct multiboot_mod_list *mod         = &mods[i];

		printk("\t- %d: [%08x, %08x)", i, mod->mod_start, mod->mod_end);

		/* These values have to be higher-half addresses */
		glb_memlayout.mod_start = chal_pa2va((paddr_t)mod->mod_start);
		glb_memlayout.mod_end   = chal_pa2va((paddr_t)mod->mod_end);
	}
	glb_memlayout.kern_boot_heap = mem_boot_start();

	printk("\tMemory regions:\n");
	for (i = 0; i < mb->mmap_length / sizeof(struct multiboot_mem_list); i++) {
		struct multiboot_mem_list *mem      = &mems[i];
		u8_t *                     mod_end  = glb_memlayout.mod_end;
		u8_t *                     mem_addr = chal_pa2va((paddr_t)mem->addr);
		unsigned long              mem_len  = (mem->len > COS_PHYMEM_MAX_SZ ? COS_PHYMEM_MAX_SZ : mem->len); /* maximum allowed */

		printk("\t- %d (%s): [%08llx, %08llx) sz = %ldMB + %ldKB\n", i, mem->type == 1 ? "Available" : "Reserved ", mem->addr,
		       mem->addr + mem->len, MEM_MB_ONLY((u32_t)mem->len), MEM_KB_ONLY((u32_t)mem->len));

		if (mem->addr > COS_PHYMEM_END_PA || mem->addr + mem_len > COS_PHYMEM_END_PA) continue;

		/* is this the memory region we'll use for component memory? */
		if (mem->type == 1 && mod_end >= mem_addr && mod_end < (mem_addr + mem_len)) {
			unsigned long sz = (mem_addr + mem_len) - mod_end;

			glb_memlayout.kmem_end = mem_addr + mem_len;
			printk("\t  memory usable at boot time: %lx (%ld MB + %ld KB)\n", sz, MEM_MB_ONLY(sz),
			       MEM_KB_ONLY(sz));
		}
	}
	/* FIXME: check memory layout vs. the multiboot memory regions... */

	/* Validate the memory layout. */
	assert(mem_kern_end() <= mem_bootc_start());
	assert(mem_bootc_end() <= mem_boot_start());
	assert(mem_boot_start() >= mem_kmem_start());
	assert(mem_kmem_start() == mem_bootc_start());
	assert(mem_kmem_end() >= mem_boot_end());
	assert(mem_utmem_start() >= mem_kmem_start());
	assert(mem_utmem_start() >= mem_boot_end());
	assert(mem_utmem_end() <= mem_kmem_end());

	wastage += mem_boot_start() - mem_bootc_end();

	printk("\tAmount of wasted memory due to layout is %u MB + 0x%x B\n", MEM_MB_ONLY(wastage), wastage & ((1 << 20) - 1));

	assert(STK_INFO_SZ == sizeof(struct cos_cpu_local_info));
}

static void out(u16_t port, u32_t value) {
	asm("out %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

void
kmain(struct multiboot *mboot, u32_t mboot_magic, u32_t esp)
{
	const char *p;
	for (p = "Hello, world!\n"; *p; ++p){
		out(0xE9, *p);
	}

#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
	unsigned long max;

	tss_init(INIT_CORE);
	for (p = "Test1\n"; *p; ++p){
		out(0xE9, *p);
	}
	gdt_init(INIT_CORE);
	for (p = "Test2\n"; *p; ++p){
		out(0xE9, *p);
	}
//	idt_init(INIT_CORE);

	for (p = "Test3\n"; *p; ++p){
		out(0xE9, *p);
	}


#ifdef ENABLE_SERIAL
//	serial_init();
#endif
#ifdef ENABLE_CONSOLE
//	console_init();
#endif
#ifdef ENABLE_VGA
//	vga_init();
#endif
	for (p = "Test4\n"; *p; ++p){
		out(0xE9, *p);
	}
	max = MAX((unsigned long)mboot->mods_addr,
	          MAX((unsigned long)mboot->mmap_addr, (unsigned long)(chal_va2pa(&end))));
	kern_paging_map_init((void *)(max + PGD_SIZE));
	for (p = "Test5\n"; *p; ++p){
		out(0xE9, *p);
	}
	kern_memory_setup(mboot, mboot_magic);
	for (p = "Test6\n"; *p; ++p){
		out(0xE9, *p);
	}

	chal_init();
	for (p = "Test7\n"; *p; ++p){
		out(0xE9, *p);
	}
	cap_init();
	for (p = "Test8\n"; *p; ++p){
		out(0xE9, *p);
	}
	ltbl_init();
	for (p = "Test9\n"; *p; ++p){
		out(0xE9, *p);
	}
	retype_tbl_init();
	for (p = "Test10\n"; *p; ++p){
		out(0xE9, *p);
	}
	comp_init();
	for (p = "Test11\n"; *p; ++p){
		out(0xE9, *p);
	}
	thd_init();
	for (p = "Test12\n"; *p; ++p){
		out(0xE9, *p);
	}
	paging_init();
	for (p = "Test13\n"; *p; ++p){
		out(0xE9, *p);
	}

	kern_boot_comp(INIT_CORE);
	for (p = "Test14\n"; *p; ++p){
		out(0xE9, *p);
	}
	lapic_init();
	for (p = "Test15\n"; *p; ++p){
		out(0xE9, *p);
	}
	timer_init();
	for (p = "Test16\n"; *p; ++p){
		out(0xE9, *p);
	}

	smp_init(cores_ready);
	for (p = "Test17\n"; *p; ++p){
		out(0xE9, *p);
	}
	cores_ready[INIT_CORE] = 1;

	kern_boot_upcall();

	/* should not get here... */
	khalt();
}

void
smp_kmain(void)
{
	volatile cpuid_t cpu_id = get_cpuid();
	struct cos_cpu_local_info *cos_info = cos_cpu_local_info();

	printk("Initializing CPU %d\n", cpu_id);
	tss_init(cpu_id);
	gdt_init(cpu_id);
	idt_init(cpu_id);

	chal_cpu_init();
	kern_boot_comp(cpu_id);
	lapic_init();

	printk("New CPU %d Booted\n", cpu_id);
	cores_ready[cpu_id] = 1;
	/* waiting for all cored booted */
	while(cores_ready[INIT_CORE] == 0);

	kern_boot_upcall();

	while(1) ;
}

void
khalt(void)
{
	printk("Shutting down...\n");
	while (1);
	asm("mov $0x53,%ah");
	asm("mov $0x07,%al");
	asm("mov $0x001,%bx");
	asm("mov $0x03,%cx");
	asm("int $0x15");
}
