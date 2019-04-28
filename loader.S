#include "cos_config.h"
#include "chal_asm_inc.h"

.set MULTIBOOT_PAGE_ALIGN,  1<<0
.set MULTIBOOT_MEMINFO,     1<<1
.set MULTIBOOT_AOUT_KLUDGE, 1<<16
.set MULTIBOOT_MAGIC,       0x1BADB002
.set MULTIBOOT_FLAGS,       MULTIBOOT_PAGE_ALIGN | MULTIBOOT_MEMINFO
.set MULTIBOOT_CHECKSUM,    -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)

.section .multiboot
.align 4
.long MULTIBOOT_MAGIC
.long MULTIBOOT_FLAGS
.long MULTIBOOT_CHECKSUM

.set STACKSIZE, 0x1000
.comm stack, (STACKSIZE * NUM_CPU), 0x1000

.globl loader
loader:
    jmp loader
	mov 	$(stack + STACKSIZE - STK_INFO_OFF), %esp
//    jmp loader
	movl	%eax, %ecx
//    jmp loader
	movl    %cr4, %eax
//    jmp loader
	orl     $((1<<4) | (1<<7)), %eax
//    jmp loader
	movl    %eax, %cr4
//    jmp loader
	movl    $(boot_comp_pgd-COS_MEM_KERN_START_VA), %eax
	movl    %eax, %cr3
//    jmp loader

	# Turn on paging.
	movl    %cr0, %eax
//    jmp loader
	orl     $(1<<31), %eax
//    jmp loader
	movl    %eax, %cr0
//    jmp loader
	cli
//    jmp loader
	pushl %esp
//    jmp loader
	pushl %ecx
//    jmp loader
	pushl %ebx
//    jmp loader

	pushl $0  /* empty return value as we're jmping, not calling */
//    jmp loader
	mov $kmain, %eax
//    jmp loader
	jmp *%eax
loader_end:
.text
