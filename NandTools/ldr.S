.globl _start
_start:
	// nand_offset should be in r31, but where we attacked it's in r25
	mr %r31, %r25
	
	// the size of the hacked sb_b is 2*0xC000 always
	lis %r4, 1
	ori %r4, %r4, 0x8000
	add %r31, %r31, %r4

	// assemble sb address
	li %r3, 0x200
	oris %r3, %r3, 0x8000
	sldi %r3, %r3, 32
	oris %r3, %r3, 1

	// load entry point to r4
	lwz %r4, 8(%r3)
	add %r3, %r3, %r4

	// set lr to point to sb entrypoint
	clrlwi %r3, %r3, 16
	addis %r3, %r3, 0x200
	mtlr %r3
	
	// reset registers and jump to lr
	li %r0, 0
	li %r1, 0
	li %r2, 0
	li %r3, 0
	li %r4, 0
	li %r5, 0
	li %r6, 0
	li %r7, 0
	li %r8, 0
	li %r9, 0
	li %r10, 0
	li %r11, 0
	li %r12, 0
	li %r13, 0
	li %r14, 0
	li %r15, 0
	li %r16, 0
	li %r17, 0
	li %r18, 0
	li %r19, 0
	li %r20, 0
	li %r21, 0
	li %r22, 0
	li %r23, 0
	li %r24, 0
	li %r25, 0
	li %r26, 0
	li %r27, 0
	li %r28, 0
	li %r29, 0
	li %r30, 0
	mtctr %r0
	blr
	
_end:
.rept (0xC000 - (_end - _start)) / 4
	b _start
.endr
